import socket
from typing import Tuple, Optional

class Connection:
    def __init__(self, host: str, port: int, listen: bool = False, existing_socket: socket.socket = None):
        self.host = host
        self.port = port
        self.listen = listen
        self.socket = existing_socket if existing_socket else socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket = None
        self.addr = None
        
        if self.listen:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)

    def connect(self):
        try:
            self.socket.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")
        except Exception as e:
            print(f"Connection failed: {e}")

    def accept_connection(self) -> Optional['Connection']:
        try:
            client_socket, addr = self.socket.accept()
            return Connection(self.host, self.port, listen=False, existing_socket=client_socket)
        except Exception as e:
            print(f"Failed to accept connection: {e}")
            return None

    def send_data(self, data: bytes):
        try:
            length = len(data)
            self.socket.sendall(length.to_bytes(4, byteorder='big'))
            self.socket.sendall(data)
        except Exception as e:
            print(f"Failed to send data: {e}")

    def receive_data(self, max_size: int = 100 * 1024 * 1024) -> Optional[bytes]:
        try:
            raw_length = self._recv_n_bytes(4)
            if not raw_length:
                print("Failed to receive data length.")
                return None
            data_length = int.from_bytes(raw_length, byteorder='big')
            if data_length > max_size:
                print("Received data exceeds allowed size. Closing connection.")
                self.close()
                return None

            data = self._recv_n_bytes(data_length)
            if data is None:
                print("Failed to receive the expected amount of data.")
                return None
            return data
        except Exception as e:
            print(f"Failed to receive data: {e}")
            return None

    def _recv_n_bytes(self, n: int) -> Optional[bytes]:
        data = b''
        while len(data) < n:
            packet = self.socket.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def close(self):
        try:
            self.socket.close()
        except Exception as e:
            print(f"Failed to close connection: {e}")
