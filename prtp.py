from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR
from enum import Enum, auto
from collections import deque
import time

PRTP_MAX_SEGMENT_SIZE = (2**16) - 1 # 16 bit segment size space for byte alignment
MSS = 1024
MAX_BUFFER_SIZE = (2**16) - 1
SEQ_SPACE = 2**16

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
        self.last_time = time.time()

        # Reliability
        self.timeout = 1
        self.eRTT = 1 # TODO: Might want to give a better initial value
        self.dRTT = 0
        # self.max_messages = ... <- We might want to limit the message queue?
        # self.window = ... <- This will likely hold a lot of data

        # Pipelining
        self.send_base = 0
        self.next_seq_num = 0
        self.recv_base = 0

        # Flow Control
        self.rwnd = MAX_BUFFER_SIZE

        # Congestion Control
        self.cwnd = MSS * 2
        self.ssthresh = 32 * 1024
        self.dup_acks = 0

        # Buffers
        self.sent_buffer = {}
        self.recv_buffer = {}

    def update_timeout(self):
            """
                Updates the timeout value based on running weighed RTT average.
                This should be run on receipt of valid ACKs.
            """
            if self.send_base in self.sent_buffer:
                entry = self.sent_buffer[self.send_base]
                
                if entry.get('retransmitted', False):
                    return

                a = 0.125
                b = 0.25
                sRTT = time.time() - entry['time']
                self.eRTT = (1-a)*self.eRTT + a*sRTT
                self.dRTT = (1-b)*self.dRTT + b*abs(sRTT - self.eRTT)
                self.timeout = self.eRTT + 4*self.dRTT
            print(f"eRTT: {self.eRTT}, dRTT: {self.dRTT}, timeout: {self.timeout}")

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
        - Pipelining: DONE
        - Flow Control: DONE
        - Congestion Control: DONE
    """
    def __init__(self, address):
        self._sock = socket(AF_INET, SOCK_DGRAM)
        self._sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self._sock.bind(address)
        self._sock.setblocking(False)
        print(f"{time.ctime()} - Socket bound to {address}")

        self.address = address
        self.connections = {} # Maps (ip,port):PRTP_Connection key-value pairs

    def close(self):
        self._sock.close()

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
        byte_arr[header.FLAGS_END:header.CHECK_END] = checksum.to_bytes(1, "big")
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
        
        if address in self.connections:
            conn = self.connections[address]
            receive_address = None

            if not self._compare_checksum(header, payload):
                return None

            if header.flags & Header.Flags.CON:
                if header.flags == Header.Flags.CON:
                    response = self._create_segment(Header.Flags.CON | Header.Flags.ACK, seq=100, ack=conn.recv_base)
                    self._sock.sendto(response, address)
                elif header.flags & Header.Flags.ACK:
                    if conn.status == Connection.Status.REQUESTED:
                        conn.status = Connection.Status.ESTABLISHED
                        conn.send_base = header.ack
                        conn.next_seq_num = header.ack
                        if 0 in conn.sent_buffer:
                            del conn.sent_buffer[0]
                        ack = self._create_segment(Header.Flags.ACK, conn.next_seq_num, conn.recv_base)
                        self._sock.sendto(ack, address)
                elif header.flags & Header.Flags.FIN:
                    conn.status = Connection.Status.CLOSING

            elif header.flags == Header.Flags.ACK:
                conn.rwnd = header.rec 
                ack_num = header.ack
                
                # Check if ACK moves window forward
                # If distance from send_base to ack_num is positive and small
                diff = self._seq_diff(ack_num, conn.send_base)
                if diff > 0 and diff < SEQ_SPACE / 2: # Valid new ACK
                    
                    conn.update_timeout()

                    print(f"ACK {ack_num} received. Sliding window.")
                    conn.cwnd += MSS * (MSS / conn.cwnd) if conn.cwnd > 0 else MSS
                    conn.dup_acks = 0

                    # Slide window
                    # Remove everything 'behind' ack_num in the circular buffer
                    keys_to_remove = []
                    for seq in list(conn.sent_buffer.keys()):
                        # If seq is "before" ack_num in circular arithmetic
                        # dist(ack, seq) is small (meaning seq is just behind ack)
                        if self._seq_diff(ack_num, seq) < SEQ_SPACE / 2 and seq != ack_num:
                            keys_to_remove.append(seq)
                    
                    for k in keys_to_remove:
                        del conn.sent_buffer[k]
                    
                    conn.send_base = ack_num
                        
                elif ack_num == conn.send_base:
                    conn.dup_acks += 1
                    if conn.dup_acks == 3:
                        print(f"Triple duplicate ACK for {ack_num}. Fast Retransmit!")
                        if conn.send_base in conn.sent_buffer:
                            self._sock.sendto(conn.sent_buffer[conn.send_base]['seg'], address)
                        conn.ssthresh = max(conn.cwnd // 2, 2 * MSS)
                        conn.cwnd = conn.ssthresh + 3 * MSS

                if conn.status == Connection.Status.RECEIVED:
                        conn.status = Connection.Status.ESTABLISHED

            elif not header.flags: # Data
                seq_num = header.seq
                
                # Flow Control Calc
                current_buffer_usage = sum(len(m) for m in conn.messages) + len(conn.recv_buffer) * MSS
                my_rwnd = max(0, MAX_BUFFER_SIZE - current_buffer_usage)

                # Accept if seq is within [recv_base, recv_base + Window)
                dist = self._seq_diff(seq_num, conn.recv_base)
                
                if dist < MAX_BUFFER_SIZE and current_buffer_usage < MAX_BUFFER_SIZE:
                    conn.recv_buffer[seq_num] = payload
                    
                    # Deliver
                    while conn.recv_base in conn.recv_buffer:
                        data = conn.recv_buffer[conn.recv_base]
                        conn.messages.append(data)
                        del conn.recv_buffer[conn.recv_base]
                        conn.recv_base = (conn.recv_base + len(data)) % SEQ_SPACE
                        # Send Window Update ACK immediately if buffer cleared?
                        
                    ack_pkt = self._create_segment(Header.Flags.ACK, 0, conn.recv_base, my_rwnd)
                    self._sock.sendto(ack_pkt, address)
                    receive_address = address
                else:
                    # Re-send ACK for current base
                    ack_pkt = self._create_segment(Header.Flags.ACK, 0, conn.recv_base, my_rwnd)
                    self._sock.sendto(ack_pkt, address)
            
            if conn.status == Connection.Status.CLOSING and not conn.messages:
                del self.connections[address]
            
            return receive_address
        else:
            if header.flags == Header.Flags.CON and self._compare_checksum(header, payload):
                conn = Connection(Connection.Status.RECEIVED)
                conn.recv_base = (header.seq + 1) % SEQ_SPACE
                self.connections[address] = conn 
                response = self._create_segment(Header.Flags.CON | Header.Flags.ACK, seq=100, ack=conn.recv_base)
                self._sock.sendto(response, address)
                return None
    
    def _seq_diff(self, a, b):
        """Returns the distance from b to a (a - b) in a circular space"""
        return (a - b) % SEQ_SPACE

    def check_timers(self, conn, address):
        if not conn.sent_buffer: return

        current_time = time.time()
        # Check oldest unacked
        if conn.send_base in conn.sent_buffer:
            entry = conn.sent_buffer[conn.send_base]
            if current_time - entry['time'] > conn.timeout:
                print(f"{time.ctime()} - Timeout detected for Seq {conn.send_base}. Retransmitting...")
                self._sock.sendto(entry['seg'], address)
                
                entry['time'] = current_time 
                entry['retransmitted'] = True
                
                # Congestion Control: Collapse CWND on timeout
                conn.ssthresh = max(conn.cwnd // 2, 2 * MSS)
                conn.cwnd = MSS
                conn.dup_acks = 0

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
            for byte in payload: check += byte
        while (check >> 8): check = (check & CHECK_BITS) + (check >> 8)

        return check ^ CHECK_BITS
    
    def _compare_checksum(self, header, payload):
        calc = self._calculate_checksum(header, payload)
        return calc == header.check
    
    def connect(self, address):
            """
                Request a PRTP connection with the host at the provided address.
                This method should be called externally as part of a running client
                or server.
            """
            if address in self.connections: return False
            
            print(f"{time.ctime()} - Connecting to {address}...")
            self.connections[address] = Connection(Connection.Status.REQUESTED)
            conn = self.connections[address]
            
            # Initial CON segment always starts at sequence 0
            segment = self._create_segment(Header.Flags.CON, seq=0)
            
            conn.sent_buffer[0] = {
                'data': b'', 
                'time': time.time(), 
                'seg': segment
            }

            self._sock.sendto(segment, address)
            
            conn.next_seq_num = (conn.next_seq_num + 1) % SEQ_SPACE
            
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
        if address not in self.connections: return False
        conn = self.connections[address]
        
        data_chunks = [payload[i:i+MSS] for i in range(0, len(payload), MSS)]
        total_chunks = len(data_chunks)
        sent_count = 0
        
        print(f"Sending {len(payload)} bytes in {total_chunks} chunks.")

        while sent_count < total_chunks or conn.sent_buffer:
            self.receive()
            self.check_timers(conn, address)

            window_limit = min(conn.cwnd, conn.rwnd)
            
            in_flight = self._seq_diff(conn.next_seq_num, conn.send_base)
            
            if sent_count < total_chunks and in_flight < window_limit:
                chunk = data_chunks[sent_count]
                seq_num = conn.next_seq_num
                
                segment = self._create_segment(flags=0, seq=seq_num, ack=conn.recv_base, payload=chunk)
                
                conn.sent_buffer[seq_num] = {
                    'data': chunk, 
                    'time': time.time(), 
                    'seg': segment
                }
                
                self._sock.sendto(segment, address)
                conn.next_seq_num = (conn.next_seq_num + len(chunk)) % SEQ_SPACE
                sent_count += 1
            
            if sent_count == total_chunks and not conn.sent_buffer:
                break

            time.sleep(0.001)
                
        return True

    def receive(self):
        """
            Receive incoming segments from the socket. This method should be
            called externally as part of a running client or server. If a
            useful message is received, this function returns the from address
            for that message, which can be used with get_message()
        """
        for addr, conn in list(self.connections.items()):
            self.check_timers(conn, addr)

        try:
            while True:
                (segment, address) = self._sock.recvfrom(PRTP_MAX_SEGMENT_SIZE)
                recv_addr = self._handle_incoming_segment(segment, address)
                if recv_addr: return recv_addr
        except BlockingIOError:
            pass
        return None
        
    def get_segment(self, address):
        if address in self.connections and (conn := self.connections[address]).messages:
            # Check if window was effectively closed before we consume data
            was_full = (MAX_BUFFER_SIZE - (sum(len(m) for m in conn.messages))) < MSS
            
            message = conn.messages.popleft()
            
            if was_full:
                current_buffer_usage = sum(len(m) for m in conn.messages) + len(conn.recv_buffer) * MSS
                new_rwnd = max(0, MAX_BUFFER_SIZE - current_buffer_usage)
                # Send Window Update
                update = self._create_segment(Header.Flags.ACK, 0, conn.recv_base, new_rwnd)
                self._sock.sendto(update, address)
                
            return message
        return None

class PRTP_server:
    def __init__(self, ip, port):
        self.sock = PRTP_socket((ip, port))
    def close(self):
        self.sock.close()

class PRTP_client:
    def __init__(self, send_ip, send_port, receive_ip, receive_port):
        self.sock = PRTP_socket((receive_ip, receive_port))
        self.send_address = (send_ip, send_port)
    def close(self):
        self.sock.close()