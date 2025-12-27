import socket
import struct

DNS_IP = "0.0.0.0"
DNS_PORT = 5000

def build_dns_header(transaction_id, rd_flag):
    flags = 0
    flags |= (1 << 15)          # QR = 1 
    flags |= (rd_flag << 8)     # copy RD bit
    # flags |= 0                  # RCODE = 0 (NOERROR). 

    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    return struct.pack(
        "!HHHHHH",
        transaction_id,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount
        )

def server():
    fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fd.bind((DNS_IP, DNS_PORT))
    print(f"DNS server listening on {DNS_IP}:{DNS_PORT}")

    while True:
        data,addr = fd.recvfrom(512)
        transaction_id = struct.unpack("!H", data[0:2])[0]
        request_flags = struct.unpack("!H", data[2:4])[0]
        rd_flag = (request_flags >> 8) & 1
        # [DNS header] [question]
        question_section = data[12:] 
        response_header = build_dns_header(transaction_id, rd_flag)
        response = response_header + question_section
        fd.sendto(response, addr)   # echo dns response header + question

if __name__ == "__main__":
    server()