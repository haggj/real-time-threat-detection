import socket
import threading
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)

HOST = "0.0.0.0"  # Standard loopback interface address (localhost)
PORT = 443  # Port to listen on (non-privileged ports are > 1023)

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(20)

logging.info(f"listen on {HOST}:{PORT}")

def get_unqiue_ips():
    ips = {}
    total_connections = 0
    with open("client_ips", "r") as f:
        for line in f:
            total_connections += 1
            ip = line.strip().split('\t')[0]
            if ip in ips:
                ips[ip] += 1
            else:
                ips[ip] = 1

    data = '\n'.join([f"{ip}\t{ips[ip]}" for ip in ips])
    res = f"""
    ----------
    Unique IPs
    ----------
    {data}
    
    Unique IPs: {len(ips)}
    Total connections: {total_connections}
    """
    return res.encode()

def client(sock):
    client_ip, client_port = sock.getpeername()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("client_ips", "a") as f:
        f.write(f"{client_ip}\t{timestamp}\n")

    data = sock.recv(1024).decode().strip()
    if data == "go":
        sock.send(get_unqiue_ips())
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()



while True:
    c, addr = server.accept()     # Establish connection with client.
    logging.info(f"{str(addr)} has connected")
    t = threading.Thread(target=client,args=(c,))
    t.start()