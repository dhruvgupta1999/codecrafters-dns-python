import socket
import logging
import struct
from dataclasses import dataclass


logging.basicConfig(level=logging.INFO)


from dataclasses import dataclass

@dataclass
class DnsHeaderAttrMeta:
    abbreviation: str
    name: str
    num_bits: int

# Constants for each DNS header field
ID       = DnsHeaderAttrMeta("ID",       "Packet Identifier",          16)
QR       = DnsHeaderAttrMeta("QR",       "Query/Response Indicator",   1)
OPCODE   = DnsHeaderAttrMeta("OPCODE",   "Operation Code",             4)
AA       = DnsHeaderAttrMeta("AA",       "Authoritative Answer",       1)
TC       = DnsHeaderAttrMeta("TC",       "Truncation",                 1)
RD       = DnsHeaderAttrMeta("RD",       "Recursion Desired",          1)
RA       = DnsHeaderAttrMeta("RA",       "Recursion Available",        1)
Z        = DnsHeaderAttrMeta("Z",        "Reserved",                   3)
RCODE    = DnsHeaderAttrMeta("RCODE",    "Response Code",              4)
QDCOUNT  = DnsHeaderAttrMeta("QDCOUNT",  "Question Count",             16)
ANCOUNT  = DnsHeaderAttrMeta("ANCOUNT",  "Answer Record Count",        16)
NSCOUNT  = DnsHeaderAttrMeta("NSCOUNT",  "Authority Record Count",     16)
ARCOUNT  = DnsHeaderAttrMeta("ARCOUNT",  "Additional Record Count",    16)




def parse_dns_header(buf):
    if len(buf) < 12:
        raise ValueError("Buffer too short to be a valid DNS header")

    # Unpack the DNS header
    (
        packet_id,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount
    ) = struct.unpack("!HHHHHH", buf[:12])

    # Extract individual flag bits
    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 0x1
    tc = (flags >> 9) & 0x1
    rd = (flags >> 8) & 0x1
    ra = (flags >> 7) & 0x1
    z = (flags >> 4) & 0x7
    rcode = flags & 0xF

    return {
        "Packet ID": packet_id,
        "QR": qr,
        "Opcode": opcode,
        "AA": aa,
        "TC": tc,
        "RD": rd,
        "RA": ra,
        "Z": z,
        "RCODE": rcode,
        "QDCOUNT": qdcount,
        "ANCOUNT": ancount,
        "NSCOUNT": nscount,
        "ARCOUNT": arcount
    }


def generate_dns_header():
    # Fixed values based on your spec
    packet_id = 1234        # 16 bits

    # Flags field (16 bits), broken down below:
    qr     = 1              # 1 bit
    opcode = 0              # 4 bits
    aa     = 0              # 1 bit
    tc     = 0              # 1 bit
    rd     = 0              # 1 bit
    ra     = 0              # 1 bit
    z      = 0              # 3 bits
    rcode  = 0              # 4 bits

    # Counts for each section
    qdcount = 0             # Question Count
    ancount = 0             # Answer Record Count
    nscount = 0             # Authority Record Count
    arcount = 0             # Additional Record Count

    # Construct the 16-bit flags field using bitwise operations
    flags = (
        (qr << 15) |
        (opcode << 11) |
        (aa << 10) |
        (tc << 9) |
        (rd << 8) |
        (ra << 7) |
        (z << 4) |
        rcode
    )

    # Pack into bytes using network byte order (big endian)
    header = struct.pack("!HHHHHH", packet_id, flags, qdcount, ancount, nscount, arcount)

    return header


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    # Uncomment this block to pass the first stage

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            # Receives 512 bytes (at most)
            buf, source = udp_socket.recvfrom(512)
            logging.info(f"data in {buf=}\n buf_len = {len(buf)}")
            response = b""
            header = generate_dns_header()
            msg = b""
            udp_socket.sendto(header+msg, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
