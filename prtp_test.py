import unittest
import threading
import time
import random
import os
from prtp import PRTP_socket, Header, Messages, MSS, MAX_BUFFER_SIZE, SEQ_SPACE

class NetworkProxy:
    # proxy to simulate network issues
    def __init__(self, real_sock, loss_rate=0.0, latency=0.0, drop_first=0):
        self._real_sock = real_sock
        self.loss_rate = loss_rate
        self.latency = latency
        self.drop_first = drop_first # Deterministic dropping
        self.drop_count = 0
        self.packets_sent = 0

    def sendto(self, data, addr):
        self.packets_sent += 1
        
        # Deterministic drop (Drop first N packets)
        if self.drop_first > 0:
            self.drop_first -= 1
            self.drop_count += 1
            return len(data)

        # Random drop
        if self.loss_rate > 0 and random.random() < self.loss_rate:
            self.drop_count += 1
            return len(data)
        
        if self.latency > 0:
            time.sleep(self.latency)

        return self._real_sock.sendto(data, addr)

    def __getattr__(self, name):
        return getattr(self._real_sock, name)

class PRTPTestBase(unittest.TestCase):
    def setUp(self):
        self.server_ip = "127.0.0.1"
        self.server_port = random.randint(20000, 30000)
        self.client_ip = "127.0.0.1"
        self.client_port = random.randint(30001, 40000)
        
        self.server_addr = (self.server_ip, self.server_port)
        self.client_addr = (self.client_ip, self.client_port)

        self.server = PRTP_socket(self.server_addr)
        self.client = PRTP_socket(self.client_addr)
        
        self.stop_threads = False
        self.server_received_data = []

    def tearDown(self):
        self.stop_threads = True
        try:
            self.client.close()
            self.server.close()
        except:
            pass
        time.sleep(0.1)

    def run_server_receiver(self, consume_delay=0.0, callback=None):
        while not self.stop_threads:
            addr = self.server.receive()
            if addr:
                # drain buffer
                while True:
                    msg = self.server.get_segment(addr)
                    if not msg: break
                    self.server_received_data.append(msg)
                    if callback: callback(msg)
            
            if consume_delay > 0:
                time.sleep(consume_delay)
            else:
                time.sleep(0.001)

class TestHandshake(PRTPTestBase):
    
    def test_basic_handshake(self):
        t = threading.Thread(target=self.run_server_receiver)
        t.start()

        start = time.time()
        res = self.client.connect(self.server_addr)
        
        self.assertTrue(res)
        self.assertIn(self.server_addr, self.client.connections)
        
        time.sleep(0.1)
        self.assertIn(self.client_addr, self.server.connections)
        
        # check seq sync
        s_conn = self.server.connections[self.client_addr]
        c_conn = self.client.connections[self.server_addr]
        self.assertEqual(c_conn.recv_base, s_conn.next_seq_num)
        print(f"Handshake took {time.time() - start:.3f}s")

    def test_handshake_syn_loss(self):
        # Drop the first 2 SYN packets to force timeout/retransmit logic
        # without relying on random probability which causes flakes.
        self.client._sock = NetworkProxy(self.client._sock, drop_first=2)
        
        t = threading.Thread(target=self.run_server_receiver)
        t.start()

        print("Connecting with forced SYN drops...")
        res = self.client.connect(self.server_addr)
        
        self.assertTrue(res)
        self.assertIn(self.server_addr, self.client.connections)
        # Ensure we actually dropped packets (and thus retransmitted)
        self.assertTrue(self.client._sock.drop_count >= 2)

class TestReliability(PRTPTestBase):

    def test_checksum_corruption(self):
        t = threading.Thread(target=self.run_server_receiver)
        t.start()
        self.client.connect(self.server_addr)

        payload = b"CorruptPayload"
        seg = self.client._create_segment(0, 100, 0, 0, payload)
        
        # flip last byte
        corrupt_seg = seg[:-1] + bytes([seg[-1] ^ 0xFF])
        self.client._sock.sendto(corrupt_seg, self.server_addr)
        
        time.sleep(0.5)
        self.assertEqual(len(self.server_received_data), 0)

    def test_retransmission_on_loss(self):
        self.client._sock = NetworkProxy(self.client._sock, loss_rate=0.3)
        
        t = threading.Thread(target=self.run_server_receiver)
        t.start()
        self.client.connect(self.server_addr)
        
        msg = b"ReliabilityCheck" * 20
        self.client.send(msg, self.server_addr)
        
        time.sleep(2)
        
        reassembled = b"".join(self.server_received_data)
        self.assertEqual(reassembled, msg)
        print(f"Recovered from {self.client._sock.drop_count} drops")

class TestPipelining(PRTPTestBase):
    
    def test_high_throughput_ordering(self):
        t = threading.Thread(target=self.run_server_receiver)
        t.start()
        self.client.connect(self.server_addr)

        # 100 chunks
        payloads = [f"{i:04d}".encode() for i in range(100)]
        full_msg = b"".join(payloads)
        
        self.client.send(full_msg, self.server_addr)
        
        time.sleep(1)
        reassembled = b"".join(self.server_received_data)
        self.assertEqual(reassembled, full_msg)

class TestFlowControl(PRTPTestBase):
    
    def test_rwnd_blocking(self):
        self.stop_threads = False 
        def slow_receiver():
            while not self.stop_threads:
                self.server.receive() # buffer but don't consume
                time.sleep(0.01)

        t = threading.Thread(target=slow_receiver)
        t.start()

        self.client.connect(self.server_addr)
        
        fill_data = b"F" * MAX_BUFFER_SIZE
        overflow_data = b"O" * MSS 

        print("Filling window...")
        self.client.send(fill_data, self.server_addr)
        
        conn = self.client.connections[self.server_addr]
        time.sleep(0.5) 
        
        print(f"Rwnd: {conn.rwnd}")
        self.assertTrue(conn.rwnd <= MSS)

        # test blocking/probing
        def release_valve():
            time.sleep(2)
            print("Releasing buffer...")
            while len(self.server.connections[self.client_addr].messages) > 0:
                self.server.get_segment(self.client_addr)

        threading.Thread(target=release_valve).start()

        start = time.time()
        self.client.send(overflow_data, self.server_addr)
        duration = time.time() - start

        self.assertGreater(duration, 1.5)

class TestCongestionControl(PRTPTestBase):
    
    def test_slow_start_growth(self):
        t = threading.Thread(target=self.run_server_receiver)
        t.start()
        self.client.connect(self.server_addr)
        
        conn = self.client.connections[self.server_addr]
        initial = conn.cwnd
        
        self.client.send(b"A" * MSS, self.server_addr)
        time.sleep(0.2)
        
        # slow start growth check
        self.assertGreaterEqual(conn.cwnd, initial + MSS)

    def test_timeout_reset(self):
        t = threading.Thread(target=self.run_server_receiver)
        t.start()
        self.client.connect(self.server_addr)
        
        conn = self.client.connections[self.server_addr]
        
        # pump cwnd
        self.client.send(b"A" * (MSS * 5), self.server_addr)
        time.sleep(0.5)
        high_cwnd = conn.cwnd

        self.client._sock = NetworkProxy(self.client._sock, loss_rate=1.0)
        
        def send_doomed():
            try:
                self.client.send(b"D" * MSS, self.server_addr)
            except:
                pass
            
        t_send = threading.Thread(target=send_doomed)
        t_send.start()
        
        time.sleep(3.0)
        
        self.assertLess(conn.cwnd, high_cwnd)
        
        self.client._sock.loss_rate = 0.0
        t_send.join()

class TestClosing(PRTPTestBase):
    
    def test_graceful_shutdown(self):
        t = threading.Thread(target=self.run_server_receiver)
        t.start()
        self.client.connect(self.server_addr)
        self.client.disconnect(self.server_addr)
        
        time.sleep(0.5)
        
        conn = self.client.connections[self.server_addr]
        valid_states = [conn.Status.CLOSING_INIT_1, conn.Status.CLOSING_INIT_2, conn.Status.CLOSING_TIMED_WAIT]
        self.assertIn(conn.status, valid_states)

class TestStress(PRTPTestBase):
    
    def test_stress_large_file_high_loss(self):
        # 30% loss, 100KB transfer
        self.client._sock = NetworkProxy(self.client._sock, loss_rate=0.3, latency=0.005)
        
        t = threading.Thread(target=self.run_server_receiver)
        t.start()
        
        if not self.client.connect(self.server_addr):
            self.fail("Connect failed")

        data = os.urandom(100 * 1024) 
        
        print("\nStarting stress test...")
        start = time.time()
        self.client.send(data, self.server_addr)
        total = time.time() - start
        
        time.sleep(2)
        
        received_bytes = b"".join(self.server_received_data)
        
        print(f"Done in {total:.2f}s. Drops: {self.client._sock.drop_count}")
        self.assertEqual(len(received_bytes), len(data))
        self.assertEqual(received_bytes, data)

if __name__ == '__main__':
    unittest.main()