import prtp

local_ip = "127.0.0.1"
local_port = 8080

server = prtp.PRTP_server(local_ip, local_port)

server.run()