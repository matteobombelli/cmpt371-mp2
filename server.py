import prtp

local_ip = "127.0.0.1"
local_port = 8080

connection = prtp.PRTP_receiver(local_ip, local_port)

connection.listen()