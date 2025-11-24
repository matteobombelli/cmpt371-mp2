import threading
import time
import random
import socket
import logging
from prtp import PRTP_client, PRTP_server, Connection

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

SERVER_ADDR = ('127.0.0.1', 8000)
CLIENT_ADDR = ('127.0.0.1', 8001)
server_msgs = []
keep_running = True

class Fuzzer:
    def __init__(self, real_socket, loss_rate=0.0, corruption_rate=0.0, delay=0.0):
        self.real_socket = real_socket
        self.loss_rate = loss_rate
        self.corruption_rate = corruption_rate
        self.delay = delay

    def sendto(self, data, address):
        # Random loss
        if random.random() < self.loss_rate:
            logging.info(f"\t[FUZZER] > Dropped {len(data)} bytes packet to {address}")
            return len(data)

        # Random corruption
        if random.random() < self.corruption_rate:
            logging.info(f"\t[FUZZER] > Corrupted packet to {address}")
            data_list = bytearray(data)
            if len(data_list) > 0:
                last_index = len(data_list) - 1
                old_val = data_list[last_index]
                new_val = old_val ^ 255
                data_list[last_index] = new_val
            data = bytes(data_list)

        # Random delay
        if self.delay > 0:
            time.sleep(self.delay * random.random())

        try:
            return self.real_socket.sendto(data, address)
        except OSError:
            return 0

    def recvfrom(self, bufsize):
        return self.real_socket.recvfrom(bufsize)
    
    def close(self):
        self.real_socket.close()

    def bind(self, addr):
        self.real_socket.bind(addr)

    def connect(self, addr):
        self.real_socket.connect(addr)
    
    def settimeout(self, t):
        self.real_socket.settimeout(t)

# Server logic function
def server_loop():
    global server_msgs
    server = PRTP_server(SERVER_ADDR[0], SERVER_ADDR[1])
    
    while keep_running:
        try:
            address = server.sock.receive()
            if address:
                while True:
                    msg = server.sock.recvfrom(address)
                    if msg:
                        server_msgs.append(msg)
                    else:
                        break
        except Exception:
            pass
    # Close
    try:
        server.close()
    except:
        pass

def start_server():
    global server_msgs, keep_running
    server_msgs = [] # Reset queue
    keep_running = True
    t = threading.Thread(target=server_loop)
    t.start()
    time.sleep(0.5)
    return t

def stop_server(t):
    global keep_running
    keep_running = False
    # Send a dummy packet to unblock the receive loop
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(b'', SERVER_ADDR)
    sock.close()
    t.join()

def inject(client_instance, loss=0.0, corrupt=0.0):
    real_sock = client_instance.sock._sock
    fuzzer = Fuzzer(real_sock, loss_rate=loss, corruption_rate=corrupt)
    client_instance.sock._sock = fuzzer
    return fuzzer

# Tests

def test_handshake():
    logging.info("\n=== Test 01: Basic Connection Handshake ===")
    t = start_server()
    
    client = PRTP_client(SERVER_ADDR[0], SERVER_ADDR[1], CLIENT_ADDR[0], CLIENT_ADDR[1])
    client.sock.connect(client.send_address)
    
    start_time = time.time()
    status = None
    
    # Wait loop
    while time.time() - start_time < 2:
        client.sock.receive()
        if client.send_address in client.sock.connections:
            conn = client.sock.connections[client.send_address]
            status = conn.status
            if status == Connection.Status.ESTABLISHED:
                break
    
    if status == Connection.Status.ESTABLISHED:
        logging.info("Handshake Successful.")
    else:
        logging.error("Handshake FAILED.")
    
    client.close()
    stop_server(t)

def test_loss():
    logging.info("\n=== Test 02: Reliability under 30% Packet Loss ===")
    t = start_server()
    
    client = PRTP_client(SERVER_ADDR[0], SERVER_ADDR[1], CLIENT_ADDR[0], CLIENT_ADDR[1])
    inject(client, loss=0.3)
    
    client.sock.connect(client.send_address)
    
    # wait for connect
    for i in range(50):
        client.sock.receive()
        if client.send_address in client.sock.connections:
             if client.sock.connections[client.send_address].status == Connection.Status.ESTABLISHED:
                 break
        time.sleep(0.05)

    # Create payload
    messages = []
    for i in range(5):
        txt = "Message " + str(i)
        messages.append(txt.encode())
    payload = b"".join(messages)

    client.sock.send(payload, client.send_address)
    
    time.sleep(3) # Wait for retries
    
    total_received = b"".join(server_msgs)
    
    if total_received == payload:
        logging.info("Reliability Passed.")
    else:
        logging.error(f"Reliability FAILED. Got {len(total_received)} bytes, expected {len(payload)}")

    client.close()
    stop_server(t)

def test_corruption():
    logging.info("\n=== Test 03: Integrity under 20% Corruption ===")
    t = start_server()

    client = PRTP_client(SERVER_ADDR[0], SERVER_ADDR[1], CLIENT_ADDR[0], CLIENT_ADDR[1])
    inject(client, corrupt=0.2)
    
    client.sock.connect(client.send_address)
    
    for i in range(50):
        client.sock.receive()
        if client.send_address in client.sock.connections:
             if client.sock.connections[client.send_address].status == Connection.Status.ESTABLISHED:
                 break
        time.sleep(0.05)

    data = b"Important Data That Must Not Be Corrupted"
    client.sock.send(data, client.send_address)
    
    time.sleep(2)
    
    total_received = b"".join(server_msgs)
    
    if total_received == data:
        logging.info("Integrity Passed.")
    else:
        logging.error("Integrity FAILED.")

    client.close()
    stop_server(t)

def test_flow():
    logging.info("\n=== Test 04: Flow Control (RWND) ===")
    t = start_server()

    client = PRTP_client(SERVER_ADDR[0], SERVER_ADDR[1], CLIENT_ADDR[0], CLIENT_ADDR[1])
    client.sock.connect(client.send_address)
    
    for i in range(50):
        client.sock.receive()
        if client.send_address in client.sock.connections:
             if client.sock.connections[client.send_address].status == Connection.Status.ESTABLISHED:
                 break
        time.sleep(0.05)

    large_payload = b"X" * (70 * 1024)
    logging.info("Sending 70KB payload...")
    
    client.sock.sendto(large_payload, client.send_address)
    
    time.sleep(1)
    
    received_len = 0
    for m in server_msgs:
        received_len += len(m)
        
    if received_len == len(large_payload):
        logging.info("Flow Control Passed.")
    else:
        logging.error(f"Flow Control FAILED. Got {received_len} bytes.")

    client.close()
    stop_server(t)

if __name__ == '__main__':
    test_handshake()
    test_loss()
    test_corruption()
    test_flow()