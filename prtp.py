from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR
from enum import Enum, auto
from collections import deque
import time
import math

PRTP_MAX_SEGMENT_SIZE = 2**16 # 16 bit segment size space for byte alignment

class Connection:
    class Status(Enum):
        REQUESTED = auto()
        RECEIVED = auto()
        ESTABLISHED = auto()
        CLOSING = auto()
        # TIMEOUT = auto()

    def __init__(self, status=Status.REQUESTED):
        self.status = status
        self.messages = deque()
        self.window = deque() # Holds [header, segment, transmission_time] pairs
        self.last_time = time.time()
        self.timeout = 0
        self.eRTT = 1 # TODO: Might want to give a better initial value
        self.dRTT = 0
        # self.max_messages = ... <- We might want to limit the message queue?

    def update_timeout(self):
        """
            Updates the timeout value based on running weighed RTT average.
            This should be run on receipt of every ACK and CON|ACK.
        """
        a = 0.125
        b = 0.25
        sRTT = time.time() - self.last_time
        self.eRTT = (1-a)*self.eRTT + a*sRTT
        self.dRTT = (1-b)*self.dRTT + b*abs(sRTT - self.eRTT)
        self.timeout = self.eRTT + 4*self.dRTT
        # print(f"eRTT: {self.eRTT}, dRTT: {self.dRTT}, timeout: {self.timeout}")

class Header:
    """
        PRTP Headers are 80 bit long sequences carrying necessary PRTP segment 
        information.

        Header Fields:
        - Flags: An 8 bit sequence for specific segment flags in the form of CAFR0000
            - C Flag: Aka CON, signals the packet is requesting a connection
            - A Flag: Aka ACK, signals the packet is acknowledging receipt
            - F Flag: Aka FIN, signals the packet is closing a connection or
                      is the last packet in transmitting a resource
            - R Flag: Aka RES, signals the connection was refused or reset
            - 0s: 4 bits of reserved padding to maintain header byte alignment
        - Checksum: An 8 bit number indicating the PRTP segment checksum.
        - Seq: A 16 bit number indicating the starting byte for the segment 
               data payload
        - Ack: A 16 bit number indicating the last acknowledged byte received 
               by the receiver.
        - Rec: A 16 bit number indicating the maximum segment size that can
               be sent to a receiver
        - Len: A 16 bit number indicating the size of the data payload in bytes.

        Header Bytestream Diagram:
        CAFR0000 00000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000
           |        |            |                |                |                |
         Flags   Checksum       Seq              Ack              Rec              Len
    """
    # Header Member Types #####################################################
    class Flags:
        CON = 0b10000000
        ACK = 0b01000000
        FIN = 0b00100000
        RES = 0b00010000

    class Field_Lengths:
        """
            Header Field Lengths in bytes
        """
        Flags = 1
        Checksum = 1
        Seq = 2
        Ack = 2
        Rec = 2
        Len = 2

    # Header Field Constants ##################################################
    # The following lengths and indexes are in bytes
    HEADER_LEN = sum(v for k,v 
                     in Field_Lengths.__dict__.items() 
                     if not k.startswith('__'))
    FLAGS_END = Field_Lengths.Flags
    CHECK_END = FLAGS_END + Field_Lengths.Checksum
    SEQ_END = CHECK_END + Field_Lengths.Seq
    ACK_END = SEQ_END + Field_Lengths.Ack
    REC_END = ACK_END + Field_Lengths.Rec
    LEN_END = REC_END + Field_Lengths.Len

    # Header Constructors #####################################################
    def __init__(self, flags=0b00000000, seq=0, ack=0, rec=0, len=0):
        self.flags = flags
        self.check = 0 # Set this during segment creation
        self.seq = seq
        self.ack = ack
        self.rec = rec
        self.len = len
        self.bytes = (flags.to_bytes(self.Field_Lengths.Flags) 
                   + self.check.to_bytes(self.Field_Lengths.Checksum)
                   + seq.to_bytes(self.Field_Lengths.Seq) 
                   + ack.to_bytes(self.Field_Lengths.Ack) 
                   + rec.to_bytes(self.Field_Lengths.Rec) 
                   + len.to_bytes(self.Field_Lengths.Len))

    @classmethod
    def from_bytes(cls, bytes):
        """
            Call this constructor when generating a PRTP_Header object from a 
            pre-existing header bytestream.
        """
        flags = int.from_bytes(bytes[0:cls.FLAGS_END])
        CON = flags&cls.Flags.CON
        ACK = flags&cls.Flags.ACK
        FIN = flags&cls.Flags.FIN
        RES = flags&cls.Flags.RES
        check = int.from_bytes(bytes[cls.FLAGS_END:cls.CHECK_END])
        seq   = int.from_bytes(bytes[cls.CHECK_END:cls.SEQ_END])
        ack   = int.from_bytes(bytes[cls.SEQ_END:cls.ACK_END])
        rec   = int.from_bytes(bytes[cls.ACK_END:cls.REC_END])
        len   = int.from_bytes(bytes[cls.REC_END:cls.LEN_END])
        header = cls(CON|ACK|FIN|RES, seq, ack, rec, len)
        header.check = check
        header.bytes = bytes
        return header
    
class PRTP_socket:
    """
        Generic PRTP non-blocking socket implementation. This class is
        responsible for proper implementation of the PRTP protocol.
        All PRTP mechanisms should be implemented within this class:
        - Connectivity: DONE
        - Reliability: DONE-ish
        - Pipelining: TODO
        - Flow Control: TODO
        - Congestion Control: TODO
    """
    def __init__(self, address):
        self._sock = socket(AF_INET, SOCK_DGRAM)
        self._sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self._sock.bind(address)
        self._sock.setblocking(False)
        print(f"{time.ctime()} - Socket bound to {address}")

        self.address = address
        self.connections = {} # Maps (ip,port):PRTP_Connection key-value pairs

    def _create_segment(self, flags=0b000, seq=0, ack=0, rec=0, payload=None):
        """
            Creates a PRTP segment in bytes form with a valid header and 
            payload. The payload must be passed in as a bytes object.
            Use this function to create PRTP segments that are ready to 
            transmit.
        """
        length = len(payload) if payload else 0
        header = Header(flags, seq, ack, rec, length)
        checksum = self._calculate_checksum(header, payload)
        byte_arr = bytearray(header.bytes)
        byte_arr[header.FLAGS_END:header.CHECK_END] = checksum.to_bytes()
        byte_arr = bytes(byte_arr)
        header.bytes = byte_arr
        header.check = checksum
        return header.bytes + payload if payload else header.bytes
                
    def _decompose_segment(self, segment):
        """
            Decomposes the given PRTP segment into a (header, payload) pair.
            Segments must be in bytes form -> generated from create_segment
            or retrieved from sock.recvfrom
        """
        boundary = Header.HEADER_LEN
        header = Header.from_bytes(segment[:boundary])
        payload = segment[boundary:]
        return (header, payload)
    
    def _handle_incoming_segment(self, segment, address):
        """
            Handles incoming PRTP segments appropriately. PRTP mechanism-specific
            functions are taken care of here; this is where we handle connectivity
            and reliability. Returns the address for the incoming segment if the
            client can do something with it (segment is not connection related and
            passes checksum matching).
        """
        (header, payload) = self._decompose_segment(segment)
        
        # Handle segment from connected host
        if address in self.connections:
            conn = self.connections[address]
            receive_address = None

            # Handle checksum
            if not self._compare_checksum(header, payload):
                # TODO: Send previous ACK (pipeline mechanism)
                print(f"{time.ctime()} - Incoming segment checksum fail...")
                return None
            
            # Handle connection related segment
            if header.flags & Header.Flags.CON:
                if header.flags & Header.Flags.ACK:
                    # Connection request was accepted
                    if conn.status == Connection.Status.REQUESTED:
                        # Confirm connection acceptance and send final ACK
                        conn.update_timeout()
                        conn.status = Connection.Status.ESTABLISHED
                        ack = self._create_segment(Header.Flags.ACK,1,1)
                        self._sock.sendto(ack, address)
                        print(f"{time.ctime()} - Connection established!")
                elif header.flags & Header.Flags.RES:
                    # Connection request was rejected
                    print(f"{time.ctime()} - Connection reset by connected host!")
                    del self.connections[address]
                elif header.flags & Header.Flags.FIN:
                    # Connection terminated by host - will finally close when message queue is empty.
                    print(f"{time.ctime()} - Connection terminated by connected host!")
                    conn.status = Connection.Status.CLOSING
            # Handle generic ACK
            elif header.flags == Header.Flags.ACK:
                print(f"{time.ctime()} - ACK Received!")
                if conn.status == Connection.Status.RECEIVED:
                        conn.status = Connection.Status.ESTABLISHED
                        print(f"{time.ctime()} - Connection established!")
                conn.update_timeout()
                # TODO: Handle what to do here (pipeline mechanism)
                receive_address = None
            # Handle regular segment
            elif not header.flags:
                print(f"{time.ctime()} - Received {len(segment)} bytes from {address} - Sending ACK!\nSegment Contents = {hex(int.from_bytes(segment))} = {segment}")
                # Add message to the queue - to be read at the users discretion
                conn.messages.append(payload)
                ack = self._create_segment(Header.Flags.ACK,1,1) # TODO: Replace this with cumulative ACK (pipeline mechanism)
                self._sock.sendto(ack, address)
                receive_address = address
            if conn.status == Connection.Status.CLOSING and not conn.messages:
                del self.connections[address]
                print(f"{time.ctime()} - Connection {address} termination has been finalized.")
            return receive_address
        # Handle connection request from unconnected host
        else:
            if header.flags == Header.Flags.CON:
                # Handle checksum
                if not self._compare_checksum(header, payload):
                    # TODO: Send previous ACK (based on pipeline)
                    ack = self._create_segment(Header.Flags.ACK, 0, 0, 0)
                    print(f"{time.ctime()} - Incoming segment checksum fail...")
                    return None

                # Accept incoming connection
                print(f"{time.ctime()} - Receiving connection request from {address}...")
                conn = Connection(Connection.Status.RECEIVED)
                self.connections[address] = conn 
                response = self._create_segment(Header.Flags.CON | Header.Flags.ACK)
                print(f"{time.ctime()} - Accepting connection...")
                self._sock.sendto(response, address)
                return None
            
    def _calculate_checksum(self, header, payload=None):
        """
            Calculates the checksum for a given header and payload as the one's
            compliment sum of each byte in the segment.
        """
        if not header: return None

        CHECK_BITS = 2**(8*Header.Field_Lengths.Checksum)-1
        check = 0
        # Add all bytes except for the checksum itself
        for byte in header.bytes[:Header.FLAGS_END]: check += byte
        for byte in header.bytes[Header.CHECK_END:]: check += byte
        if payload: 
            for byte in payload:                     check += byte
        while (check >> 8): check = (check & CHECK_BITS) + (check >> 8)

        return check ^ CHECK_BITS
    
    def _compare_checksum(self, header, payload):
        CHECK_BITS = 2**(8*Header.Field_Lengths.Checksum)-1
        return self._calculate_checksum(header, payload) + (header.check ^ CHECK_BITS) == CHECK_BITS
    
    def connect(self, address):
        """
            Request a PRTP connection with the host at the provided address.
            This method should be called externally as part of a running client
            or server.
        """
        if address in self.connections:
            return False
        else:
            print(f"{time.ctime()} - Connecting to {address}...")
            self.connections[address] = Connection(Connection.Status.REQUESTED)
            segment = self._create_segment(Header.Flags.CON)
            print(f"{time.ctime()} - Sending {hex(int.from_bytes(segment))} to {address}...")
            self._sock.sendto(segment, address)
            return True
    
    def disconnect(self, address):
        """
            Inform connected host that you are terminating the connection.
            This method should be called externally as part of a running client
            or server.
        """
        if address in self.connections:
            segment = self._create_segment(Header.Flags.CON | Header.Flags.FIN)
            self._sock.sendto(segment, address)
            del self.connections[address]

    def send(self, payload, address):
        """
            Slices the payload into segments and sends it to the provided 
            address. The socket must have have an ongoing connection with 
            the provided address in accordance to PRTP reliability standards.
            This method should be called externally as part of a running client
            or server.
        """
        if address in self.connections:
            # TODO: Implement pipeline functionality here.
            # It could work if we slice the payload into a number of chunks
            # based on the maximum segment size, and alternate between sending
            # segments and handling ACKs. The pipelining, flow control, and
            # congestion control will likely all come into play here.
            segment = self._create_segment(0,0,0,payload=payload)
            print(f"{time.ctime()} - Sending {hex(int.from_bytes(segment))} to {address}...")
            self._sock.sendto(segment, address)
            return True
        else:
            return False

    def receive(self):
        """
            Receive incoming segments from the socket. This method should be
            called externally as part of a running client or server. If a
            useful message is received, this function returns the from address
            for that message, which can be used with get_message()
        """
        try:
            (segment, address) = self._sock.recvfrom(PRTP_MAX_SEGMENT_SIZE)
            return self._handle_incoming_segment(segment, address)
        except BlockingIOError:
            return None
        
    def get_segment(self, address):
        """
            Gets the first incoming message in the queue for the provided
            address as long as there is an active connection with it.
        """
        if address in self.connections and (conn := self.connections[address]).messages:
            message = conn.messages.popleft()
            if conn.status == Connection.Status.CLOSING and not conn.messages:
                # Terminate closing connection on empty message queue
                del self.connections[address]
            return message
        else: 
            return None

class PRTP_server:
    def __init__(self, ip, port):
        self.sock = PRTP_socket((ip, port))

    def run(self):
        """
            Handle server responsibilities
        """
        while True:
            if address := self.sock.receive():
                payload = self.sock.get_segment(address)

class PRTP_client:
    def __init__(self, send_ip, send_port, receive_ip, receive_port):
        self.sock = PRTP_socket((receive_ip, receive_port))
        self.send_address = (send_ip, send_port)

    def run(self):
        """
            Handles client responsibilities
        """
        # Send connection request to server
        self.sock.connect(self.send_address)
        timeout = 10000
        while timeout and self.sock.connections[self.send_address].status is not Connection.Status.ESTABLISHED:
            address = self.sock.receive()
            timeout-=1
        
        # Wait for handshake
        if self.sock.connections[self.send_address].status is not Connection.Status.ESTABLISHED:
            print("Connection refused or timed out...")
            return

        # Connection accepted - time to talk
        for i in range(5):
            self.sock.send("Hello, World!".encode(), self.send_address)
            address = self.sock.receive()
            payload = self.sock.get_segment(address)
            if payload: print(payload)
        for i in range(10000):
            self.sock.receive()
        self.sock.disconnect(self.send_address)