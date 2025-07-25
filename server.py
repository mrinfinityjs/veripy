import asyncio
import ssl
import json
import hashlib
import time
import os
import importlib.util
import importlib
import sys
import secrets
import argparse # <--- 1. Import argparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- Server State (Unchanged) ---
MODS_DIR = "./mods"
module_metadata = {}
ACTIVE_CLIENTS = set()

# --- Helper and Core Functions (Unchanged) ---
def get_public_key_fingerprint(client_cert_bytes):
    try:
        cert = x509.load_der_x509_certificate(client_cert_bytes, default_backend())
        public_key = cert.public_key()
        pub_key_bytes = public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return hashlib.sha256(pub_key_bytes).hexdigest()
    except Exception as e: print(f"Error processing certificate: {e}"); return None

def get_file_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""): sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

async def broadcast(message):
    if not ACTIVE_CLIENTS: return
    print(f"[Broadcast] Sending to {len(ACTIVE_CLIENTS)} clients: {message.strip()}")
    for writer in list(ACTIVE_CLIENTS):
        try:
            writer.write(message.encode())
            await writer.drain()
        except ConnectionError:
            ACTIVE_CLIENTS.discard(writer)

def load_or_reload_module(filename):
    module_name = filename[:-3]
    filepath = os.path.join(MODS_DIR, filename)
    try:
        file_sum = get_file_sha256(filepath)
        module_info = module_metadata.get(filename)
        if module_info:
            print(f"  -> Reloading module: {filename}")
            module = module_info['module']
            module.__spec__.loader.exec_module(module)
        else:
            print(f"  -> Loading new module: {filename}")
            spec = importlib.util.spec_from_file_location(module_name, filepath)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
        if not (hasattr(module, "execute") and asyncio.iscoroutinefunction(module.execute)):
            raise AttributeError("Module missing 'async def execute(args)' function.")
        desc = getattr(module, 'description', 'No description.')
        module_metadata[filename] = {"module": module, "desc": desc, "sum": file_sum, "spec": module.__spec__}
        return {"mod": filename, "desc": desc, "sum": file_sum}
    except Exception as e:
        print(f"  -! ERROR with module {filename}: {e}")
        return None

def unload_module(filename):
    if filename in module_metadata:
        print(f"  -> Unloading module: {filename}")
        metadata = module_metadata.pop(filename)
        module_name = filename[:-3]
        if module_name in sys.modules: del sys.modules[module_name]
        return {"mod": filename, "desc": metadata['desc'], "sum": metadata['sum']}
    return None

def initial_load_mods():
    if not os.path.isdir(MODS_DIR): os.makedirs(MODS_DIR)
    print(f"--- Performing initial module scan in '{MODS_DIR}' ---")
    for filename in os.listdir(MODS_DIR):
        if filename.endswith(".py") and not filename.startswith("__"):
            load_or_reload_module(filename)
    print("--- Initial module scan complete ---")

class ModuleChangeHandler(FileSystemEventHandler):
    def __init__(self, loop):
        self.loop = loop
    def _broadcast_event(self, event_type, filename):
        print(f"\n[Watcher] Event: {event_type} on file: '{filename}'")
        if event_type == 'deleted': metadata = unload_module(filename)
        else: metadata = load_or_reload_module(filename)
        if metadata:
            msg_type = {'created': 'modload', 'modified': 'modreload', 'deleted': 'modunload'}.get(event_type)
            ref = secrets.token_hex(4)
            message = f"{msg_type}:{msg_type}:{ref} {json.dumps(metadata)}\n"
            asyncio.run_coroutine_threadsafe(broadcast(message), self.loop)
    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith(".py"): self._broadcast_event('created', os.path.basename(event.src_path))
    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith(".py"): self._broadcast_event('modified', os.path.basename(event.src_path))
    def on_deleted(self, event):
        if not event.is_directory and event.src_path.endswith(".py"): self._broadcast_event('deleted', os.path.basename(event.src_path))

async def handle_client(reader, writer):
    # (This function is unchanged)
    addr = writer.get_extra_info('peername')
    ssl_object = writer.get_extra_info('ssl_object')
    client_cert = ssl_object.getpeercert(binary_form=True)
    fingerprint = get_public_key_fingerprint(client_cert)
    try:
        with open('trusted-keys.json', 'r') as f:
            trusted_fingerprints = json.load(f).get('trusted_fingerprints', [])
    except (FileNotFoundError, json.JSONDecodeError): trusted_fingerprints = []
    if fingerprint not in trusted_fingerprints:
        print(f"Untrusted fingerprint from {addr}. Closing."); writer.close(); await writer.wait_closed(); return
    print(f"Trusted connection from {addr}."); ACTIVE_CLIENTS.add(writer)
    try:
        while True:
            data = await reader.read(4096)
            if not data: break
            incoming_buffer = data.decode()
            for message in incoming_buffer.strip().split('\n'):
                if not message: continue
                print(f"Processing from {addr}: {message}")
                try:
                    header, json_payload = message.split(' ', 1)
                    api_cmd, sub_cmd, reference = header.split(':', 2)
                    request_data = json.loads(json_payload)
                    response_message = ""
                    if api_cmd == 'mod':
                        if sub_cmd == 'sync':
                            all_mods = [{"mod": name, "desc": meta['desc'], "sum": meta['sum']} for name, meta in module_metadata.items()]
                            response_payload = {"modules": all_mods}
                            response_message = f"mod:sync_resp:{reference} {json.dumps(response_payload)}\n"
                        elif sub_cmd == 'verify':
                            mod_to_verify = request_data.get('mod')
                            mod_path = os.path.join(MODS_DIR, mod_to_verify)
                            if os.path.exists(mod_path) and mod_to_verify in module_metadata:
                                with open(mod_path, 'r') as f: content = f.read()
                                meta = module_metadata[mod_to_verify]
                                response_payload = {"mod": mod_to_verify, "content": content, "sum": meta['sum'], "desc": meta['desc']}
                            else:
                                response_payload = {"mod": mod_to_verify, "error": "Module not found on server."}
                            response_message = f"mod:verify_resp:{reference} {json.dumps(response_payload)}\n"
                    if response_message: writer.write(response_message.encode()); await writer.drain()
                except Exception as e: print(f"Error parsing/executing command: {e}")
    except ConnectionResetError: print(f"Client {addr} disconnected.")
    except Exception as e: print(f"Error with client {addr}: {e}")
    finally:
        ACTIVE_CLIENTS.discard(writer)
        if not writer.is_closing(): writer.close(); await writer.wait_closed()
        print(f"Connection with {addr} closed. {len(ACTIVE_CLIENTS)} clients remaining.")

async def main():
    # --- 2. Argument Parsing Logic ---
    parser = argparse.ArgumentParser(description="Async EC SSL API Server with dynamic modules.")
    parser.add_argument(
        '-i', '--interface',
        type=str,
        default='localhost',
        help='The network interface to bind to (e.g., "127.0.0.1", "0.0.0.0"). Default is localhost.'
    )
    parser.add_argument(
        '-p', '--port',
        type=int,
        default=8443,
        help='The port to listen on. Default is 8443.'
    )
    args = parser.parse_args()
    
    # Use the parsed arguments instead of hardcoded values
    host = args.interface
    port = args.port

    initial_load_mods()
    
    main_loop = asyncio.get_running_loop()
    event_handler = ModuleChangeHandler(loop=main_loop)
    observer = Observer()
    observer.schedule(event_handler, MODS_DIR, recursive=False)
    observer.start()
    print(f"--- File watcher started on '{MODS_DIR}' ---")

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain("server.crt", "server.key")
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations("client.crt")
    
    server = await asyncio.start_server(handle_client, host, port, ssl=context)
    print(f'Serving on {", ".join(str(s.getsockname()) for s in server.sockets)}...')
    
    try:
        async with server:
            await server.serve_forever()
    finally:
        print("\n--- Shutting down file watcher ---")
        observer.stop()
        observer.join()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer shut down by user.")
