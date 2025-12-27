import socket

DNS_IP = "0.0.0.0"
DNS_PORT = 5000

def server():
    fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fd.bind((DNS_IP, DNS_PORT))
    print(f"DNS server listening on {DNS_IP}:{DNS_PORT}")

    while True:
        data,addr = fd.recvfrom(512)
        print(f"[>] Received {len(data)} bytes from {addr}")
        fd.sendto(data, addr)   # echo message
        print(f"[<] Sent {len(data)} bytes back to {addr}")

if __name__ == "__main__":
    server()