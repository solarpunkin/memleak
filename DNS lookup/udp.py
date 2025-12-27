from bz2 import compress
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

def compressor(data, offset):
    labels = []
    jumped = False
    original_offset = offset
    while True:
        length = data[offset]
        if (length & 0xC0) == 0xC0:
            pt = struct.unpack("!H", data[offset:offset+2])[0]
            offset = pt & 0x3FFF
            jumped = True
            continue

        # end of name
        if length == 0:
            offset+=1
            break

        offset += 1
        label = data[offset:offset+length].decode("ascii")
        labels.append(label)
        offset+=length

    name = ".".join(labels)
    if jumped:
        return name, original_offset + 2
    else:
        return name, offset

def header_parser(data):
    if len(data) < 12:
        raise ValueError("Packet too short to be DNS")
    (transaction_id, flags, qdcount, ancount, nscount, arcount) = struct.unpack("!HHHHHH", data[:12])
    header = {
        "id": transaction_id,
        "flags": flags,
        "qr": (flags >> 15) & 1,
        "opcode": (flags >> 11) & 0xF,
        "aa": (flags >> 10) & 1,
        "tc": (flags >> 9) & 1,
        "rd": (flags >> 8) & 1,
        "ra": (flags >> 7) & 1,
        "rcode": flags & 0xF,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
    }
    return header

def question_parser(data, offset = 12):
    qname, offset = compressor(data, offset)
    qtype, qclass = struct.unpack("!HH", data[offset:offset+4])
    offset+=4
    question = {"qname": qname, "qtype": qtype, "qclass": qclass, "end_offset": offset}
    return question

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
        # header parser
        header = header_parser(data)
        print(
        f"[DNS] id={header['id']} "
        f"qr={header['qr']} rd={header['rd']} "
        f"qd={header['qdcount']} an={header['ancount']} "
        f"ar={header['arcount']}"
)   
        # question parser (1 question)
        question = question_parser(data)
        print(
        f"[Q] name={question['qname']} "
        f"type={question['qtype']} "
        f"class={question['qclass']}"
)
        # [DNS header] [question]
        question_section = extract_question(data) 
        answer = build_answer_section()
        response_header = build_dns_header(transaction_id, rd_flag, ancount=1)
        response = response_header + question_section + answer
        fd.sendto(response, addr)   # echo dns response header + question + answer (hardcoded)

if __name__ == "__main__":
    server()