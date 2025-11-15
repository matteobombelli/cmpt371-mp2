import socket
from enum import Enum, auto
import math

class Connection_Status(Enum):
    NEW = auto()
    CONNECTED = auto()
    CLOSING = auto()    


class PRTP_Connection:
    def __init__(self, address):
        self.address = address
        self.status = Connection_Status.NEW
        # self.window = ...

# TODO
# Make header class use more defined masks/flags
class PRTP_Header:
    """
        First bit: Request_Connection
        Second bit: Accept_Connection
        Third bit: Close_Connection
    """

    def __init__(self, bytestream):
        self.bytestream = bytestream

        # Seq. #: int
    
    def __init__(self, 
        req=False, 
        acc=False,
        fin=False):
        if req:
            self.bytestream = 0b100
        if acc:
            self.bytestream = 0b010
        if fin:
            self.bytestream = 0b001

    def get_REQ(self):
        return self.bytestream & 0b100
    
    def get_ACC(self):
        return self.bytestream & 0b010
    
    def get_FIN(self):
        return self.bytestream & 0b001


class PRTP_receiver:
    def __init__(self, ip, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.buffer = 1024
        self.ip = ip
        self.port = port
        self.connections = {}

    def _parse_header(self, payload):
        return True

    def _handle_connection(self, payload, address):
        header = self._parse_header(payload)
        
        if header:
            newPRTPConnection = PRTP_Connection(address)
            self.connections[address] = newPRTPConnection
            new_header = PRTP_Header(acc=True)
            self.respond(new_header.bytestream, 0b0, address)

    def _handle_datagram(self, payload, connection):
        print(payload)
        print(connection)

    def respond(self, header, payload, address):
        header_bytes = header.to_bytes()
        payload_bytes = payload.to_bytes()
        self.socket.sendto(header_bytes + payload_bytes, address)

    def listen(self):
        self.socket.bind((self.ip, self.port))
        self.socket.setblocking(False)

        while True:
            try:
                datagram = self.socket.recvfrom(self.buffer)
                payload = datagram[0]
                address = datagram[1]
                if address in self.connections:
                    self._handle_datagram(payload, (self.connections.get(address)))
                else:
                    # TODO: Check requesting connection
                    self._handle_connection(payload, address)
            except BlockingIOError:
                pass


class PRTP_sender:
    def __init__(self, send_ip, send_port, receive_ip, receive_port):
        self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.receive_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.send_ip = send_ip
        self.send_port = send_port
        self.receive_ip = receive_ip
        self.receive_port = receive_port
    
    def listen(self):
        # Send request to server
        self.send()

        # Wait for accept
        self.socket.bind((self.receive_ip, self.receive_port))

        while True:
            datagram = self.socket.recvfrom(self.buffer)
            payload = datagram[0]
            address = datagram[1]
            if address == (self.send_ip, self.send_port):
            
            # Check we received accept
            # If accept, break this loop
            # Otherwise, return (close connection)
            # TODO: timeout

        print("Successfully connected!")
        # while True:
            # Main loop for receiving packets and sending ACKs

    def send(self):
        new_header = PRTP_Header(req=True)
        self.send_socket.sendto(new_header.bytestream.to_bytes(), (self.ip, self.port))