import prtp

server_ip = "127.0.0.1"
server_port = 8080
local_ip = "127.0.0.1"
local_port = 8081

client = prtp.PRTP_client(server_ip, server_port, local_ip, local_port)

client.run()