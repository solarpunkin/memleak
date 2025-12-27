import socket
import struct

DNS_IP = "0.0.0.0"
DNS_PORT = 5000

# hepler to extract question section from dig query
# can be skipped to question parsing stage 
# but added here for answer verification

def extract_question(data):
    offset = 12
    # skip QNAME(labels)
    while data[offset] != 0:
        offset+=1
    offset+=1
    # QTYPE(2) + QCLASS(2)
    offset+=4
    return data[12:offset]

def build_dns_header(transaction_id, rd_flag, ancount):
    flags = 0
    flags |= (1 << 15)          # QR = 1 
    flags |= (rd_flag << 8)     # copy RD bit
    # flags |= 0                  # RCODE = 0 (NOERROR). 

    qdcount = 1
    # ancount = 0
    nscount = 0
    arcount = 0

    return struct.pack(
        "!HHHHHH", transaction_id, flags, qdcount, ancount, nscount, arcount)

def build_answer_section():
    name = 0xC00C   # name compression (pointer to QNAME)
    rtype = 1       # A
    rclass = 1      # IN
    ttl = 60
    rdlength = 4    # IPv4
    rdata = socket.inet_aton("1.2.3.4")

    return struct.pack("!HHHLH4s", name, rtype, rclass, ttl, rdlength, rdata)

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
        question_section = extract_question(data) 
        answer = build_answer_section()
        response_header = build_dns_header(transaction_id, rd_flag, ancount=1)
        response = response_header + question_section + answer
        fd.sendto(response, addr)   # echo dns response header + question + answer (hardcoded)

if __name__ == "__main__":
    server()