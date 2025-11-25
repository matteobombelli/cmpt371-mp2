import prtp

server_address = ('127.0.0.1', '8000')
serve = prtp.socket(server_address)

client_address = ('127.0.0.1', '8001')
client = prtp.socket(client_address)

if client.connect(server_address):
    client.sendto("Hello, world!".to_bytes(), server_address)

message = serve.recvfrom(client_address)