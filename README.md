
# Nectar2P

**Nectar2P** — A secure and fast open-source Python library for P2P file transfers, featuring optional encryption and NAT traversal support. With nectar2p, you can easily transfer files between devices on the same network or across different networks.

## Features

- **Secure File Transfer**: Provides RSA and AES encryption for secure data transmission.
- **Optional Encryption**: Enable or disable encryption for file transfer as per requirement.
- **NAT Traversal**: Supports connections between devices behind NATs.
- **Modular Design**: Easily integrable and customizable for various use cases.
- **Format Support**: Nectar2P supports all file formats.

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

### Basic Usage

#### File Sending (Sender)

```python
from nectar2p.nectar_sender import NectarSender

def main():
    receiver_host = "public.receiver.ip"
    receiver_port = 5000
    sender = NectarSender(receiver_host, receiver_port, enable_encryption=True)

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
    receiver = NectarReceiver(host, port, enable_encryption=True)

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

### Enabling/Disabling Encryption

Encryption can be optionally enabled or disabled during file transfer. When `enable_encryption` is set to `True`, RSA and AES encryption are used. When set to `False`, files are transferred without encryption.

```python
# Encryption enabled
sender = NectarSender("receiver_ip", 5000, enable_encryption=True)

# Encryption disabled
receiver = NectarReceiver("0.0.0.0", 5000, enable_encryption=False)
```

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

## Support the Project

[![Buy Me A Coffee](https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png)](https://www.buymeacoffee.com/glimor)
