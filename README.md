
# Nectar2P

**Nectar2P** — A secure and fast open-source Python library for P2P file transfers, featuring optional encryption and NAT traversal support. With nectar2p, you can easily transfer files between devices on the same network or across different networks.

## Features

- **Secure File Transfer**: Provides RSA and AES-GCM encryption for confidentiality and integrity.
- **Optional Encryption**: Enable or disable encryption for file transfer as per requirement.
- **NAT Traversal**: Supports connections between devices behind NATs.
- **Peer Authentication**: Allows verification of the remote party's RSA public key to prevent MITM attacks.
- **Security Hardened**: Protection against path traversal, DoS attacks, replay attacks, and other common vulnerabilities.
- **Modular Design**: Easily integrable and customizable for various use cases.
- **Format Support**: Nectar2P supports all file formats.
- **Command Line Interface**: `python -m nectar2p` provides simple `send`, `receive`, and `export-key` commands with progress display.
- **Integrity & Resume**: Transfers include SHA-256 verification and can resume from partial files.

## Installation

`nectar2p` requires Python 3.6+ and depends on the `cryptography` library. Follow these steps to install the project:

```bash
# Install Nectar2P
pip install nectar2p
```

## Usage

### Overview

`nectar2p` provides two main classes for P2P file transfer:
- **NectarSender**: Used for sending files.
- **NectarReceiver**: Used for receiving files.

These classes support secure file transfer with optional encryption and NAT traversal.

### Command Line Usage

After installing the package you can use a simple CLI:

#### Basic Transfer

```bash
# Start receiver
python -m nectar2p receive 0.0.0.0 5000 received.bin --resume
```

In another terminal:

```bash
# Send file
python -m nectar2p send receiver_ip 5000 file.bin
```

#### Secure Transfer with Public Key Verification

To prevent Man-in-the-Middle (MITM) attacks, you can verify the identity of the remote party using their public key:

```bash
# Step 1: Both parties export their public keys
python -m nectar2p export-key sender_public.pem
python -m nectar2p export-key receiver_public.pem

# Step 2: Exchange public keys through a secure channel (e.g., in person, encrypted email)

# Step 3: Receiver starts with sender's public key verification
python -m nectar2p receive 0.0.0.0 5000 received.bin --verify-key sender_public.pem

# Step 4: Sender connects with receiver's public key verification
python -m nectar2p send receiver_ip 5000 file.bin --verify-key receiver_public.pem
```

#### Additional Options

```bash
# Disable encryption (not recommended for sensitive data)
python -m nectar2p send receiver_ip 5000 file.bin --no-encryption

# Use custom STUN server for NAT traversal
python -m nectar2p send receiver_ip 5000 file.bin --stun-host stun.example.com --stun-port 3478

# Resume interrupted transfer
python -m nectar2p receive 0.0.0.0 5000 received.bin --resume
```

### Basic Usage

#### File Sending (Sender)

```python
from nectar2p.nectar_sender import NectarSender

def main():
    receiver_host = "public.receiver.ip"
    receiver_port = 5000
    # optionally verify the receiver's public key
    expected_receiver_key = b"-----BEGIN PUBLIC KEY-----..."
    sender = NectarSender(receiver_host, receiver_port, enable_encryption=True,
                          expected_receiver_public_key=expected_receiver_key)

    try:
        sender.initiate_secure_connection()
        sender.send_file("path/to/your/file.txt")
    finally:
        sender.close_connection()

if __name__ == "__main__":
    main()
```

#### File Receiving (Receiver)

```python
from nectar2p.nectar_receiver import NectarReceiver

def main():
    host = "0.0.0.0"  # Allows connection from any IP
    port = 5000
    # optionally verify the sender's public key
    expected_sender_key = b"-----BEGIN PUBLIC KEY-----..."
    receiver = NectarReceiver(host, port, enable_encryption=True,
                              expected_sender_public_key=expected_sender_key)

    try:
        receiver.wait_for_sender()
        receiver.receive_file("path/to/save/file.txt")
    finally:
        receiver.close_connection()

if __name__ == "__main__":
    main()
```

### Using NAT Traversal for Cross-Network Transfers

The `NectarSender` and `NectarReceiver` classes use a STUN server for NAT traversal, allowing direct connections between devices on different networks. Public IP addresses are automatically retrieved through the STUN server.
The STUN server address can be customized when creating `NATTraversal`. Be aware that the server can observe your public IP address.

### Enabling/Disabling Encryption

Encryption can be optionally enabled or disabled during file transfer. When `enable_encryption` is set to `True`, RSA and AES-GCM encryption are used. When set to `False`, files are transferred without encryption. Files are transferred in 64&nbsp;KiB chunks and each chunk is authenticated. `Connection.receive_data` enforces a maximum message size of 100&nbsp;MiB by default.

**Security Note**: Encryption is strongly recommended for sensitive data. When encryption is enabled, the library uses:
- RSA-2048 for key exchange
- AES-256-GCM for data encryption
- Cryptographically secure random number generation
- Nonce reuse detection to prevent replay attacks

```python
# Encryption enabled
sender = NectarSender("receiver_ip", 5000, enable_encryption=True)

# Encryption disabled
receiver = NectarReceiver("0.0.0.0", 5000, enable_encryption=False)
```

## Security Features

Nectar2P includes multiple security layers to protect your file transfers:

- **MITM Protection**: Public key verification prevents man-in-the-middle attacks
- **Path Traversal Protection**: Files can only be saved within the working directory
- **DoS Protection**: Connection timeouts (30s), buffer limits (1MB), and file size limits (10GB)
- **Replay Attack Protection**: Nonce reuse detection prevents message replay attacks
- **Input Validation**: Port numbers, file sizes, and offsets are validated
- **Secure Randomness**: Uses `secrets` module for cryptographic operations
- **Error Message Security**: Generic error messages prevent information leakage

## Project Structure

Explanation of main files and folders used in the project:

```
nectar2p/
├── nectar2p/
│   ├── __init__.py                # Main package file
│   ├── nectar_sender.py           # Class managing file sending operations
│   ├── nectar_receiver.py         # Class managing file receiving operations
│   ├── encryption/
│   │   ├── __init__.py            # Encryption module
│   │   ├── rsa_handler.py         # RSA operations
│   │   └── aes_handler.py         # AES operations
│   ├── networking/
│   │   ├── __init__.py            # Networking module
│   │   ├── connection.py          # Connection operations
│   │   └── nat_traversal.py       # NAT traversal operations
├── setup.py                       # Setup file
└── README.md                      # Project overview and instructions
```

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Contributing

Contributions are welcome! Feel free to submit `pull requests` or open `issues` on GitHub for any bugs, suggestions, or improvements.

## Contact

For any questions or suggestions, please feel free to reach out: [glimor@proton.me](mailto:glimor@proton.me)

