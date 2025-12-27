import time
import socket
import struct

DNS_IP = "0.0.0.0"
DNS_PORT = 5000
UPSTREAM_DNS = ("8.8.8.8", 53)
cache = {}
def forward_query(query_data):
    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up.settimeout(2)
    up.sendto(query_data, UPSTREAM_DNS)
    response, _ = up.recvfrom(4096)         # safe: EDNS may exceed 512 
    up.close()
    return response

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

# extract minimum TTL from answer RR to cache
def extract_ttl(data, answer_count, offset):
    ttls=[]
    for _ in range(answer_count):
        _, offset = compressor(data, offset)
        _, _, ttl, rdlength = struct.unpack("!HHLH", data[offset:offset+10])
        offset += 10
        offset += rdlength
        ttls.append(ttl)
    return min(ttls) if ttls else 0

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


def server():
    fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fd.bind((DNS_IP, DNS_PORT))
    print(f"DNS server listening on {DNS_IP}:{DNS_PORT}")

    while True:
        data,addr = fd.recvfrom(512)
        
        # header parser
        header = header_parser(data)
        # print(f"[DNS] id={header['id']} " f"qr={header['qr']} rd={header['rd']} " f"qd={header['qdcount']} an={header['ancount']} " f"ar={header['arcount']}")   
        
        # question parser (1 question) 
        # [DNS header] [question]
        question = question_parser(data)
        # print(f"[Q] name={question['qname']} " f"type={question['qtype']} " f"class={question['qclass']}")
        
        key = (question["qname"], question["qtype"], question["qclass"])
        
        # cache hit
        if key in cache and cache[key]["expires_at"] > time.time():
            cached = cache[key]["response"]
            response = struct.pack("!H", header["id"]) + cached[2:]
            fd.sendto(response, addr)
            print("[CACHE HIT]", key)
            continue
        
        # cache miss -> forward
        upstream_response = forward_query(data)
        up_header = header_parser(upstream_response)

        if up_header["ancount"] > 0:
            ttl = extract_ttl(upstream_response, up_header["ancount"], question_parser(upstream_response)["end_offset"])
            cache[key] = {
                "response": upstream_response,
                "expires_at": time.time() + max(ttl, 30)    # keep TTL for atleast 30 seconds
            }
        response = struct.pack("!H", header["id"]) + upstream_response[2:]
        fd.sendto(response, addr)   # return dns response message 

if __name__ == "__main__":
    server()