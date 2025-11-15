import socket
from enum import Enum, auto
import math
import time

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
        con=False, 
        acc=False,
        fin=False):
        if con:
            self.bytestream = 0b100
        if acc:
            self.bytestream = 0b010
        if fin:
            self.bytestream = 0b001
            
    def get_CON(self):
        return self.bytestream & 0b100
    
    def get_ACC(self):
        return self.bytestream & 0b010
    
    def get_FIN(self):
        return self.bytestream & 0b001


class PRTP_server:
    def __init__(self, ip, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.buffer = 4096 # Maximum PRTP segment size
        self.address = (ip, port)
        self.connections = {}

    def _parse_header(self, payload):
        return True

    def _handle_connection(self, payload, address):
        header = self._parse_header(payload)
        
        if header:
            newPRTPConnection = PRTP_Connection(address)
            self.connections[address] = newPRTPConnection
            new_header = PRTP_Header(acc=True)
            self.send(new_header.bytestream, 0b0, address)

    def _handle_datagram(self, payload, connection): # TODO: Expand on this (or replace?)
        print(payload)
        print(connection)

    def send(self, header, payload, address):
    # Sends a PRTP packet with the given header and payload to the given address
        header_bytes = header.to_bytes()   # TODO: Come back to this - are we doing this right?
        payload_bytes = payload.to_bytes() # TODO: Come back to this - are we doing this right?
        self.sock.sendto(header_bytes + payload_bytes, address)

    def run(self):
    # Handles server responsibilities
        # Initialize socket
        self.sock.bind(self.address)
        self.sock.setblocking(False)

        while True:
            try:
                datagram = self.sock.recvfrom(self.buffer)
                payload = datagram[0]
                address = datagram[1]
                if address in self.connections:
                    print(f"Existing connection: {address}")
                    self._handle_datagram(payload, (self.connections.get(address)))
                else:
                    # TODO: Check requesting connection
                    print(f"New connection: {address}")
                    self._handle_connection(payload, address)
            except BlockingIOError:
                pass

class PRTP_client:
    def __init__(self, send_ip, send_port, receive_ip, receive_port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.buffer = 4096 # Maximum PRTP segment size
        self.send_address = (send_ip, send_port)
        self.receive_address = (receive_ip, receive_port)
    
    def run(self):
    # Handles client responsibilities
        # Initialize socket
        self.sock.bind(self.receive_address)

        # Send connection request to server
        self.connect()
        datagram = self.receive()
        if datagram:
            # TODO: Check whether this message is an "Accept_Connection" message. (We are just assuming rn.)
            print(datagram)
        else:
            print("Connection request not reciprocated... closing client...")
            return

        # Connection accepted
        # TODO: Handle subsequent packets from server + handle ACKs
        self.send(0, "Hello World!", self.send_address) # This is just a test message...
        datagram = self.receive()
        print(datagram)

    def connect(self): #TODO: We can probably replace this just with send()
        new_header = PRTP_Header(con=True)
        self.sock.sendto(new_header.bytestream.to_bytes(), self.send_address)
        
    def send(self, header, payload, address):
    # Sends a PRTP packet with the given header and payload to the given address
        header_bytes = header.to_bytes() # TODO: Come back to this - are we doing this right?
        payload_bytes = payload.encode() # TODO: Come back to this - are we doing this right?
        self.sock.sendto(header_bytes + payload_bytes, address)

    def receive(self):
    # Receive segments and handle them appropriately
        # Wait for accept
        timer = 10000 # TODO: Implement RTT based timer. Fuse with pipeline functionality.
        while timer:
            datagram = self.sock.recvfrom(self.buffer)
            print(f"Message received")
            # TODO: Utilize checksum
            payload = datagram[0]
            address = datagram[1]
            if address == self.send_address:
                return datagram
            timer-=1
        if not timer:
            print("Timeout...")
            return