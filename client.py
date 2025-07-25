import asyncio
import ssl
import json
import secrets
import time
import hashlib

SERVER_MODULES = {}
pending_requests = {}
WRITER_REF = None

def get_string_sha256(content):
    return hashlib.sha256(content.encode()).hexdigest()

def handle_sync_response(data):
    print("\n[Sync] Received full module list from server. Verifying each module...")
    modules_to_verify = data.get('modules', [])
    if not modules_to_verify:
        print("--- Server has no modules loaded. ---")
    # Trigger verification for all modules received in the sync
    for mod_info in modules_to_verify:
        asyncio.create_task(request_verification(mod_info['mod']))

def handle_verify_response(data):
    """Handles verification and is the ONLY place that should add to SERVER_MODULES."""
    mod_name = data.get('mod')
    content = data.get('content')
    server_sum = data.get('sum')
    desc = data.get('desc', 'No description.')
    
    print(f"\n[Verify] Verifying content of '{mod_name}'...")
    if not content:
        print(f"  ❌ FAILURE: Could not get content for {mod_name}: {data.get('error')}")
        SERVER_MODULES.pop(mod_name, None) # Remove if it exists
        return
        
    client_sum = get_string_sha256(content)
    print(f"  Server's Hash: {server_sum}")
    print(f"  Client's Hash: {client_sum}")
    
    if client_sum == server_sum:
        print(f"  ✅ SUCCESS: Hashes match for '{mod_name}'. Module is now trusted.")
        # This is now the single point of truth for adding/updating the local cache.
        SERVER_MODULES[mod_name] = {"mod": mod_name, "desc": desc, "sum": server_sum}
    else:
        print(f"  ❌ FAILURE: Hashes DO NOT match for '{mod_name}'! Module is untrusted.")
        SERVER_MODULES.pop(mod_name, None) # Remove if it exists

def handle_broadcast(api_cmd, data):
    """Handles broadcasts, triggering verification instead of blindly trusting."""
    mod_name = data.get('mod')
    if not mod_name: return
    
    if api_cmd == 'modunload':
        print(f"\n[Broadcast] Module unloaded on server: {mod_name}")
        if mod_name in SERVER_MODULES:
            del SERVER_MODULES[mod_name]
    # --- THIS IS THE KEY CHANGE ---
    elif api_cmd in ['modload', 'modreload']:
        event_type = "loaded" if api_cmd == 'modload' else "reloaded"
        print(f"\n[Broadcast] Server reports module '{mod_name}' was {event_type}.")
        # Instead of trusting, we initiate our own verification.
        asyncio.create_task(request_verification(mod_name))

async def request_verification(mod_name):
    """Sends a mod:verify request for a specific module."""
    if not WRITER_REF or WRITER_REF.is_closing():
        print("[Verify] Cannot send request, writer is not available.")
        return
    
    print(f"  -> Initiating verification for '{mod_name}'...")
    verify_ref = secrets.token_hex(8)
    pending_requests[verify_ref] = {'cmd': 'verify', 'mod': mod_name}
    verify_payload = {'mod': mod_name}
    verify_message = f"mod:verify:{verify_ref} {json.dumps(verify_payload)}\n"
    WRITER_REF.write(verify_message.encode())
    await WRITER_REF.drain()

async def listen_for_messages(reader):
    while True:
        try:
            data = await reader.read(4096)
            if not data: print("\nServer closed the connection. Exiting."); break
            for response_message in data.decode().strip().split('\n'):
                if not response_message: continue
                try:
                    header, json_payload = response_message.split(' ', 1)
                    resp_data = json.loads(json_payload)
                    api_cmd, msg_type, reference = header.split(':', 2)
                    
                    if reference in pending_requests:
                        pending_requests.pop(reference)
                        if msg_type == 'sync_resp': handle_sync_response(resp_data)
                        elif msg_type == 'verify_resp': handle_verify_response(resp_data)
                    elif msg_type in ['modload', 'modreload', 'modunload']:
                        handle_broadcast(msg_type, resp_data)
                    else:
                        print(f"\n[Warning] Received unhandled message: {response_message}")
                except (ValueError, json.JSONDecodeError) as e:
                    print(f"\n--- ❌ Error parsing server message: {e} ---")
                    print(f"Raw data: {response_message}")
        except ConnectionResetError: print("\nConnection was reset. Exiting."); break
        except asyncio.CancelledError: break

async def main_workflow(writer):
    await asyncio.sleep(0.1)
    print("--- Starting client workflow ---")
    sync_ref = secrets.token_hex(8)
    pending_requests[sync_ref] = {'cmd': 'sync'}
    sync_message = f"mod:sync:{sync_ref} {json.dumps({})}\n"
    print(f"\nRequesting initial module sync from server...")
    writer.write(sync_message.encode())
    await writer.drain()
    print("\n--- Workflow complete. Idling for broadcast messages (Press Ctrl+C to exit) ---")

async def run_client():
    global WRITER_REF
    host = 'localhost'
    port = 8443
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="server.crt")
    context.load_cert_chain(certfile="client.crt", keyfile="client.key")
    
    try:
        reader, writer = await asyncio.open_connection(host, port, ssl=context)
        WRITER_REF = writer
        listener_task = asyncio.create_task(listen_for_messages(reader))
        await main_workflow(writer)
        await listener_task
    except ConnectionRefusedError: print("Connection refused. Is the server running?")
    except ssl.SSLError as e: print(f"SSL Error: {e}. Check certs.")
    except asyncio.CancelledError: print("\nClient shutting down.")
    except Exception as e: print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(run_client())
    except KeyboardInterrupt:
        print("\nClient shut down by user.")
