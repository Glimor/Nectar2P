import socket
import struct
import random
from typing import Tuple

class NATTraversal:
    def __init__(self, stun_server: Tuple[str, int] | None = ("stun4.l.google.com", 19302)):
        self.stun_server = stun_server

    def get_public_address(self) -> Tuple[str, int]:
        if not self.stun_server:
            return "0.0.0.0", 0

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(10)
        
        msg_type = 0x0001
        msg_length = 0
        transaction_id = random.getrandbits(128).to_bytes(16, 'big')
        stun_msg = struct.pack("!HH16s", msg_type, msg_length, transaction_id)
        
        try:
            sock.sendto(stun_msg, self.stun_server)
            data, addr = sock.recvfrom(1024)
        except (socket.timeout, OSError):
            sock.close()
            raise Exception("STUN request timeout")
        
        sock.close()
        
        if len(data) < 20:
            raise Exception("Invalid STUN response")
        
        resp_type, resp_length = struct.unpack("!HH", data[:4])
        if resp_type != 0x0101:
            raise Exception(f"Unexpected STUN response type: 0x{resp_type:04x}")
        
        attrs = data[20:]
        i = 0
        public_ip = None
        public_port = None
        while i < len(attrs):
            if i + 4 > len(attrs):
                break
            attr_type, attr_length = struct.unpack("!HH", attrs[i:i+4])
            i += 4
            if i + attr_length > len(attrs):
                break
            attr_value = attrs[i:i+attr_length]
            
            if attr_type == 0x0001:
                if attr_length >= 8:
                    port = struct.unpack("!H", attr_value[2:4])[0]
                    ip = socket.inet_ntoa(attr_value[4:8])
                    public_ip = ip
                    public_port = port
                    break

            i += attr_length
        
        if public_ip and public_port:
            return public_ip, public_port
        else:
            raise Exception("Failed to retrieve public IP and port")
