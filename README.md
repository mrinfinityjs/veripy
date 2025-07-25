# VeriPy

A Secure, Dynamic, and Verifiable Python Client-Server Framework.

VeriPy is a robust, asynchronous client-server framework built with Python's `asyncio`. It provides a secure communication channel using mutual TLS (mTLS) with Elliptic Curve cryptography and a powerful, dynamic plugin system for extending server functionality in real-time without restarts.

The core philosophy of VeriPy is **"verify, then trust."** The server verifies clients by their public key fingerprints, and the client actively verifies the integrity of server-side modules via cryptographic hashes, ensuring a secure and synchronized state.

## Core Features

-   **Secure by Default:** Implements mutual TLS (mTLS) where both the server and client must present valid, trusted certificates to communicate.
-   **Fingerprint Authentication:** The server authenticates clients based on a trusted list of public key SHA256 fingerprints, not just a shared Certificate Authority.
-   **Fully Asynchronous:** Built entirely on Python's `asyncio` for high-performance, concurrent handling of multiple clients.
-   **Dynamic Module System:** The server features a hot-pluggable module system. Simply drop a Python file into the `./mods` directory to add new API commands.
-   **Live Reloading:** The server uses `watchdog` to monitor the `./mods` directory. Any changes to a module file are detected and the module is reloaded in real-time, without any server downtime.
-   **State Synchronization & Broadcasting:** The server broadcasts critical events (module load, reload, unload) to all connected clients, allowing them to stay in sync.
-   **Client-Side Integrity Verification:** The client doesn't blindly trust broadcasts. Upon notification of a module change, it automatically requests the module's source code and verifies its SHA256 hash against the server's reported hash.
-   **Configurable:** The server's listening interface and port can be easily configured via command-line arguments.
-   **Modern Tooling:** Uses `uv` for fast and efficient project environment and dependency management.

## Getting Started

### Prerequisites

-   Python 3.10+
-   `uv` (for environment and package management). If you don't have it, install it via `pip`:
    ```bash
    pip install uv
    ```-   `openssl` command-line tool for generating certificates.

### 1. Installation

First, clone the repository and navigate into the project directory.

```bash
git clone <url>
cd veripy
```

Next, use `uv` to create a virtual environment and install the required dependencies.

```bash
# Create a virtual environment in the .venv directory
uv venv

# Activate the environment
# On macOS/Linux:
source .venv/bin/activate
# On Windows:
.venv\Scripts\Activate.ps1

# Install dependencies using uv
uv pip install -r requirements.txt
```

*(Note: You will need to create a `requirements.txt` file containing `cryptography` and `watchdog`.)*

### 2. Configuration

VeriPy relies on SSL certificates and a trusted key store for its security model.

#### Certificate Generation

You need to generate self-signed certificates for both the server and the client. The following commands use the high-performance `EC25519` curve.

```bash
# 1. Generate the server's private key and certificate
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:ed25519 -nodes -keyout server.key -out server.crt -subj "/CN=VeriPyServer"

# 2. Generate the client's private key and certificate
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:ed25519 -nodes -keyout client.key -out client.crt -subj "/CN=VeriPyClient"
```

These commands will create `server.crt`, `server.key`, `client.crt`, and `client.key` in your project directory.

#### Trusted Client Fingerprint

The server needs to know which clients to trust. You do this by adding the SHA256 fingerprint of the client's public key to `trusted-keys.json`.

1.  **Generate the fingerprint:** Run this command to extract the public key from the client certificate and hash it.

    ```bash
    openssl x509 -in client.crt -pubkey -noout | openssl pkey -pubin -outform der | sha256sum | awk '{print $1}'
    ```

2.  **Create `trusted-keys.json`:** Create a new file named `trusted-keys.json` and add the fingerprint you generated.

    ```json
    {
      "trusted_fingerprints": [
        "PASTE_THE_FINGERPRINT_HASH_HERE"
      ]
    }
    ```

## Creating Modules

To add a new command to the server, simply create a new `.py` file in the `./mods` directory.

The module file must contain:
1.  An optional `description` string variable.
2.  An `async def execute(args_string: str)` function that performs the action and returns a string result.

**Example: `./mods/hello.py`**```python
# ./mods/hello.py

# A description that the client will see.
description = "A simple module that says hello to a name."

async def execute(args_string: str):
    """
    Greets the name provided in the arguments.
    
    Args:
        args_string: The name to greet.
    
    Returns:
        A greeting string.
    """
    if not args_string:
        return "You didn't tell me who to greet!"
    
    return f"Hello, {args_string}!"
```

The server will automatically load this new module when you create the file.

## Usage

### Running the Server

Start the server from the project's root directory.

```bash
# Run on the default localhost:8443
python server.py

# Run on a different port
python server.py --port 9000

# Run on all network interfaces (e.g., for connecting from another machine)
python server.py --interface 0.0.0.0

# See all options
python server.py --help
```

### Running the Client

Open a second terminal, activate the virtual environment (`source .venv/bin/activate`), and run the client.

```bash
python client.py
```

The client will automatically:
1.  Request a full list of modules from the server (`mod:sync`).
2.  Receive the list and trigger an integrity verification for each module.
3.  Upon successful verification, trust the modules.
4.  Idle and listen for broadcast messages from the server.
5.  If a `modreload` event is received, it will automatically re-verify the integrity of the changed module.

## API Protocol

Communication follows a standard `API:TYPE:REFERENCE {payload}` format.

### Client to Server

-   `mod:sync:<ref> {}`: Request the full list of loaded modules.
-   `mod:verify:<ref> {"mod": "filename.py"}`: Request the source code and hash for a specific module to verify its integrity.
-   `mod:exec:<ref> {"mod": "filename.py", "args": "-a"}`: Execute a specific module with arguments.

### Server to Client

-   `mod:sync_resp:<ref> {"modules": [...]}`: The response to a `sync` request, containing a list of all module metadata.
-   `mod:verify_resp:<ref> {"mod": "...", "content": "...", "sum": "...", "desc": "..."}`: The response to a `verify` request.
-   `modload:modload:<ref> {"mod": "...", ...}`: Broadcast sent to all clients when a new module is loaded.
-   `modreload:modreload:<ref> {"mod": "...", ...}`: Broadcast sent when a module is changed and reloaded.
-   `modunload:modunload:<ref> {"mod": "...", ...}`: Broadcast sent when a module file is deleted.

## Dependencies

-   `cryptography`: For handling certificates and public keys.
-   `watchdog`: For monitoring the `./mods` directory for changes.
