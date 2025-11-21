import socket
from enum import Enum, auto
from collections import deque

PRTP_MAX_SEGMENT_SIZE = 2**16 # 16 bit segment size space for byte alignment

class PRTP_Connection:
    class Status(Enum):
        NEW = auto()
        CONNECTED = auto()
        CLOSING = auto()
        # TIMEOUT = auto()

    def __init__(self):
        self.status = self.Status.NEW
        self.messages = deque()
        # self.max_messages = ... -> We might want to limit the message queue?
        # self.window = ... -> This will likely hold a lot of data
        # self.eRTT = ...

class PRTP_Header:
    """
        PRTP Headers are 80 bit long sequences carrying necessary PRTP segment 
        information.

        Header Fields:
        - Flags: An 8 bit sequence for specific segment flags in the form of CAF00000
            - C Flag: Aka CON, signals the packet is requesting a connection
            - A Flag: Aka ACC, signals the packet is affirming a connection
            - F Flag: Aka FIN, signals the packet is closing a connection or
                      is the last packet in transmitting a resource
            - 0s: 5 bits of reserved padding to maintain header byte alignment
        - SEQ: A 16 bit number indicating the starting byte for the segment 
               data payload
        - ACK: A 16 bit number indicating the last acknowledged byte received 
               by the receiver.
        - REC: A 16 bit number indicating the maximum segment size that can
               be sent to a receiver
        - LEN: A 16 bit number indicating the size of the data payload in bytes.
        - Checksum: An 8 bit number indicating the PRTP segment checksum.

        Header Bytestream Diagram:
         CAF00000 00000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000
            |        |            |                |                |                |
          Flags   Checksum       SEQ              ACK              REC              LEN
    """
    # Header Member Types #####################################################
    class Flags:
        CON = 0b10000000
        ACC = 0b01000000
        FIN = 0b00100000

    class Field_Lengths:
        """
            Header Field Lengths in bytes
        """
        Flags = 1
        Checksum = 1
        SEQ = 2
        ACK = 2
        REC = 2
        LEN = 2

    # Header Field Constants ##################################################
    # The following lengths and indexes are in bytes
    HEADER_LEN = sum(v for k,v 
                     in Field_Lengths.__dict__.items() 
                     if not k.startswith('__'))
    FLAGS_END = Field_Lengths.Flags
    CHECK_END = FLAGS_END + Field_Lengths.Checksum
    SEQ_END = CHECK_END + Field_Lengths.SEQ
    ACK_END = SEQ_END + Field_Lengths.ACK
    REC_END = ACK_END + Field_Lengths.REC
    LEN_END = REC_END + Field_Lengths.LEN

    # Header Constructors #####################################################
    def __init__(self, flags=0b000, seq=0, ack=0, rec=0, len=0):
        self.flags = flags
        self.check = 0 # Set this during segment creation
        self.seq = seq
        self.ack = ack
        self.rec = rec
        self.len = len
        self.bytes = (flags.to_bytes(self.Field_Lengths.Flags) 
                   + self.check.to_bytes(self.Field_Lengths.Checksum)
                   + seq.to_bytes(self.Field_Lengths.SEQ) 
                   + ack.to_bytes(self.Field_Lengths.ACK) 
                   + rec.to_bytes(self.Field_Lengths.REC) 
                   + len.to_bytes(self.Field_Lengths.LEN))

    @classmethod
    def from_bytes(cls, bytes):
        """
            Call this constructor when generating a PRTP_Header object from a 
            pre-existing header bytestream.
        """
        flags = int.from_bytes(bytes[0:cls.FLAGS_END])
        con = flags&cls.Flags.CON
        acc = flags&cls.Flags.ACC
        fin = flags&cls.Flags.FIN
        check = int.from_bytes(bytes[cls.LEN_END:cls.CHECK_END])
        seq   = int.from_bytes(bytes[cls.FLAGS_END:cls.SEQ_END])
        ack   = int.from_bytes(bytes[cls.SEQ_END:cls.ACK_END])
        rec   = int.from_bytes(bytes[cls.ACK_END:cls.REC_END])
        len   = int.from_bytes(bytes[cls.REC_END:cls.LEN_END])
        header = cls(con|acc|fin,seq,ack,rec,len)
        header.check = check
        header.bytes = bytes
        return header
    
class PRTP_socket:
    """
        Generic PRTP non-blocking socket implementation. This class is
        responsible for proper implementation of the PRTP protocol.
        All PRTP mechanisms should be implemented within this class:
        - Connectivity: TODO
        - Reliability: TODO
        - Pipelining: TODO
        - Flow Control: TODO
        - Congestion Control: TODO
    """
    def __init__(self, address):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(address)
        self._sock.setblocking(False)
        print(f"Socket bound to {address}")

        self.address = address
        self.connections = {} # Maps (ip,port):PRTP_Connection key-value pairs

    def _create_segment(self, flags=0b000, seq=0, ack=0, payload=None):
        """
            Creates a PRTP segment in bytes form with a valid header and 
            payload. The payload must be passed in as a bytes object.
            Use this function to create PRTP segments that are ready to 
            transmit.
        """
        if payload:
            length = len(payload)
            header = PRTP_Header(flags, seq, ack, length)
            # checksum = self.calculate_checksum(header)
            # header.bytes[header.FLAGS_END:header.CHECK_END] = checksum
            # header.check = checksum
            return header.bytes + payload
        else:
            header = PRTP_Header(flags,seq,ack,0)
            # checksum = self.calculate_checksum(header)
            # header.bytes[header.FLAGS_END:header.CHECK_END] = checksum
            # header.check = checksum
            return header.bytes
        
    def _decompose_segment(self, segment):
        """
            Decomposes the given PRTP segment into a (header, payload) pair.
            Segments must be in bytes form -> generated from create_segment
            or retrieved from sock.recvfrom
        """
        boundary = PRTP_Header.HEADER_LEN
        header = PRTP_Header.from_bytes(segment[:boundary])
        payload = segment[boundary:]
        return (header, payload)
    
    def _handle_segment(self, segment, address):
        """
            Handles incoming PRTP segments appropriately. PRTP mechanism-specific
            functions are taken care of here; this is where we handle connectivity
            and reliability. Returns the address for the incoming segment if the
            client can do something with it (segment is not connection related and
            passes checksum matching).
        """
        (header, payload) = self._decompose_segment(segment)
        if address in self.connections:
            # TODO: Implement reliability mechanism
            # Once we do, compare the checksum here

            # TODO: Handle connectivity mechanism ACC properly (this is just a placeholder)
            if header.flags & PRTP_Header.Flags.ACC:
                print("Connection request accepted!")
                if self.connections[address].status == PRTP_Connection.Status.NEW:
                    self.connections[address].status = PRTP_Connection.Status.CONNECTED
                    # TODO: Send ACK here - To establish RTT for the acceptor
                    return None
            elif not header.flags:
                # Add message to the queue - to be read at the users discretion
                self.connections[address].messages.append((header, payload))
                # TODO: Send ACK here
                return address
        else:
            # TODO: Implement reliability mechanism
            # Once we do, compare the checksum here
            
            # TODO: Handle connectivity mechanism CON properly (this is just a placeholder)
            if header.flags & PRTP_Header.Flags.CON:
                print(f"Receiving connection request from {address}...")
                self.connections[address] = PRTP_Connection()
                response = self._create_segment(PRTP_Header.Flags.ACC)
                self.send(response, address)
                return None
            
    # def _calculate_checksum(self, header):
    #     # TODO: Implement checksum logic! (Self hint: Skip over checksum bytes for compatibility with compare_checksum)
    #     print("TODO: Implement checksum logic!")
    #     return 0
    
    # def _compare_checksum(self, header):
    #     return header.check == self._calculate_checksum(header)
    
    def connect(self, address):
        """
            Request a PRTP connection with the host at the provided address
        """
        if address in self.connections:
            return False
        else:
            print(f"Connecting to {address}...")
            self.connections[address] = PRTP_Connection()
            segment = self._create_segment(PRTP_Header.Flags.CON)
            self.send(segment, address)
            return True
    
    def disconnect(self, address):
        """
            Inform connected host that you are terminating the connection
        """
        if address in self.connections:
            segment = self._create_segment(PRTP_Header.Flags.FIN)
            self.send(segment, address)
            del self.connections[address]

    def send(self, payload, address):
        """
            Slices the payload into segments and sends it to the provided 
            address. The socket must have have an ongoing connection with 
            the provided address in accordance to PRTP reliability standards.
        """
        if address in self.connections:
            # TODO: Implement pipeline functionality here.
            # It could work if we slice the payload into a number of chunks
            # based on the maximum segment size, and alternate between sending
            # segments and handling ACKs. The pipelining, flow control, and
            # congestion control will likely all come into play here.
            segment = self._create_segment(0,0,0,payload=payload)
            print(f"Sending {bin(int.from_bytes(segment))} to {address}...")
            self._sock.sendto(segment, address)
            return True
        else:
            return False

    def receive(self):
        """
            Receive segments from the socket
        """
        try:
            (segment, address) = self._sock.recvfrom(PRTP_MAX_SEGMENT_SIZE)
            print(f"Message of length {len(segment)} received from {address}:\n{bin(int.from_bytes(segment))} = {segment}")
            return self._handle_segment(segment, address)
        except BlockingIOError:
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
                (header, payload) = self.sock.connections[address].messages.popleft()
                self.sock.send("OK".encode(), address)

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
        timeout = 10000 # TODO: Choose a more suitable connection request timeout value
        while timeout and self.sock.connections[self.send_address].status is not PRTP_Connection.Status.CONNECTED:
            address = self.sock.receive()
            timeout-=1
        
        # Wait for handshake
        if self.sock.connections[self.send_address].status is not PRTP_Connection.Status.CONNECTED:
            print("Connection refused or timed out...")
            return

        # Connection accepted - time to talk
        #segment = self.sock.create_segment(0,0,0,"Hello, World!".encode()) # This is just a test message...
        self.sock.send("Hello, World!".encode(), self.send_address) 
        while not self.sock.receive(): continue
        segment = self.sock.connections[self.send_address].messages.popleft()
        print(segment)