import argparse
import socket
import logging
import struct

"""
https://github.com/EmilHernvall/dnsguide/blob/b52da3b32b27c81e5c6729ac14fe01fef8b1b593/chapter1.md


DNS packet:
1. header
2. question : domainName for which I want the IP address, type, class
3. answer : empty for client packets, the IP address is filled in the answer section in packets 
            sent by DNS server.
            


Header section Attributes (you don't really need to know much here):
    * id [16 bits] (Packet Identifier)
        - A random ID assigned to query packets. Response packets must reply with the same ID.
    * QR [1 bit] (Query/Response Indicator)
        - 1 for a reply packet, 0 for a question packet.
    * OPCODE [4 bits] (Operation Code)
        - Specifies the kind of query in a message.
    * AA [1 bit] (Authoritative Answer)
        - 1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    * TC [1 bit] (Truncation)
        - 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    * RD [1 bit] (Recursion Desired)
        - Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    * RA [1 bit] (Recursion Available)
        - Server sets this to 1 to indicate that recursion is available.
    * Z [3 bits] (Reserved)
        - Used by DNSSEC queries. At inception, it was reserved for future use.
    * RCODE [4 bits] (Response Code)
        - Response code indicating the status of the response.
    * QDCOUNT [16 bits] (Question Count)
        - Number of questions in the Question section.
    * ANCOUNT [16 bits] (Answer Record Count)
        - Number of records in the Answer section.
    * NSCOUNT [16 bits] (Authority Record Count)
        - Number of records in the Authority section.
    * ARCOUNT [16 bits] (Additional Record Count)
        - Number of records in the Additional section.
"""

"""

label encoding:
The domain name is encoded using <label_len1><label1>..<label_leni><labeli><null_byte> pattern.
eg:
a.google.com is encoded as [1]a[6]google[3]com[null_byte] in the question section.

Compression in DNS:
Since the client might send multiple questions in the question section for the same domain.
eg:
Give me IP address for a.google.com, b.google.com, def.google.com (each domain here may actually map to different IPs)
Here google.com is repeating again and again and we can't waste space in our 512 bytes packet, so we use compression.

How compression works:
If label_length_byte > 0xC0 (2 MSB are set)
Then remaining 6 bits of length byte + the next byte = 14 bits.

These 14 bits point to the byte index in the entire received packet 
where the remaining part of domain name can be found.

eg:
a.google.com is encoded as [1]a[6]google[3]com[null_byte]
b.google.com is encoded as [1]b[2bits_pointer_incoming_!!][14bits_packet_address of [6]google[3]com]


Server Forwarding:
If my DNS server doesn't have the domain to IP mapping for a given request.
It asks another server, and returns the answer to the client.
1.1.1.1:53 is a worldwide DNS server managed by cloudflare. 
You can use this to test your code.

"""


# label encoding: [6]google[3]com followed by a null byte b'\x00'.
CODECRAFTERS_DOMAIN_LABEL_ENCODED = b'\x0ccodecrafters\x02io\x00'

def parse_dns_header(buf):
    """
    Parses the DNS header from the given byte buffer.

    Args:
        buf (bytes): The byte buffer containing the DNS packet.

    Returns:
        dict: A dictionary containing the parsed header fields and their values.

    Raises:
        ValueError: If the buffer is too short to contain a valid DNS header.
    """
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

    header = {
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
    print(f"received header:\n {header}")
    return header


def generate_dns_header(*, question_count=0, answer_count=0, packet_id=1234,
                        opcode=0, rd=0, response_code=0, qr=1):
    """
    Generates a DNS header with the specified parameters.

    Args:
        question_count (int): Number of questions in the packet.
        answer_count (int): Number of answers in the packet.
        packet_id (int): Packet identifier.
        opcode (int): Operation code.
        rd (int): Recursion desired flag.
        response_code (int): Response code (RCODE).
        qr (int): Query/Response indicator (0 for query, 1 for response).

    Returns:
        bytes: The packed DNS header as bytes.
    """
    # Fixed values based on your spec
    packet_id = packet_id        # 16 bits

    # Flags field (16 bits), broken down below:
    qr     = qr              # 1 bit
    opcode = opcode              # 4 bits
    aa     = 0              # 1 bit
    tc     = 0              # 1 bit
    rd     = rd              # 1 bit
    ra     = 0              # 1 bit
    z      = 0              # 3 bits
    rcode  = response_code              # 4 bits

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

    # Counts for each section
    qdcount = question_count             # Question Count
    ancount = answer_count             # Answer Record Count
    nscount = 0             # Authority Record Count
    arcount = 0             # Additional Record Count

    print(f"Response header: {packet_id=}, {flags=}, {qdcount=}, {ancount=}, {nscount=}, {arcount=}")

    # Pack into bytes using network byte order (big endian)
    header = struct.pack("!HHHHHH", packet_id, flags, qdcount, ancount, nscount, arcount)

    return header


def parse_label_encoded_domain(question_bytes) -> tuple[str, int]:
    """
    Parses a label-encoded domain name from the given bytes.

    Args:
        question_bytes (bytes): The bytes containing the label-encoded domain.

    Returns:
        tuple[str, int]: The domain as a string and the index just after the end of the label-encoded domain.
    """
    """
    Return the domain string and the index just after the end (null byte) of the label
    encoded domain.

    """
    # Here you need to parse label encoding.
    labels = []
    idx = 0
    while idx < len(question_bytes):
        byt = question_bytes[idx]
        # Each byte is automatically treated as an integer.
        # domain ends with null byte
        if byt == 0:
            idx += 1
            break
        label_len = byt
        labels.append(question_bytes[idx + 1:idx + 1 + label_len])
        idx = idx + 1 + label_len
    domain = '.'.join(labels)
    return domain, idx

def get_label_encoded_domain_suffix(packet, start_idx):
    """
    Retrieves the label-encoded domain suffix from the packet starting at the given index.
    In DNS name compression, a compressed domain uses a pointer (the first two bits set to 1)
    to refer to the remainder of the domain name that appears earlier in the DNS packet.
    This function extracts the full label-encoded domain, following the pointer if present.


    Args:
        packet (bytes): The full DNS packet.
        start_idx (int): The index to start reading the domain suffix from.

    Returns:
        bytes: The label-encoded domain suffix including the null byte.

    Raises:
        ValueError: If no null byte is found indicating the end of the domain.
    """
    idx = start_idx
    while idx < len(packet):
        # look for null byte
        if packet[idx] == 0:
            return packet[start_idx: idx+1]
        idx += 1
    raise ValueError("Couldn't find any null byte to indicate the end of domain.")

def parse_dns_question(packet, start_idx):
    """
    Parses a single DNS question from the packet starting at the given index.

    Args:
        packet (bytes): The full DNS packet.
        start_idx (int): The index where the question starts.

    Returns:
        tuple: (label_encoded_domain, type, class_field, next_index)
            label_encoded_domain (bytes): The label-encoded domain name.
            type (int): The type of the DNS query.
            class_field (int): The class of the DNS query.
            next_index (int): The index just after the end of this question.
    """

    # ignore header part
    idx = start_idx
    label_encoded_domain = b''
    while idx < len(packet):
        print(f"in loop, {idx=}")
        byt = packet[idx]

        if byt == 0:
            # null byte
            label_encoded_domain += b'\x00'
            idx += 1
            break
        # Is it a pointer instead ?
        if (byt & 0xC0) == 0xC0:
            # Get the remaining 6 bits + next byte to get the address of the remaining domain name.
            remaining_domain_address = int.from_bytes(packet[idx:idx+2]) ^ 0xC000
            print("found a pointer.")
            print(f"prefix: {label_encoded_domain}")
            print(f"domain suffix byte index in packet: {remaining_domain_address}")
            domain_suffix = get_label_encoded_domain_suffix(packet, remaining_domain_address)
            print(f"suffix: {domain_suffix}")
            label_encoded_domain += domain_suffix
            idx += 2
            break

        label_len = byt
        label_encoded_domain += packet[idx:idx + 1 + label_len]
        idx = idx + 1 + label_len

    assert idx < len(packet)
    typ = int.from_bytes(packet[idx:idx + 2])
    class_field = int.from_bytes(packet[idx + 2:idx + 4])
    print("Received question:")
    print(f"{label_encoded_domain=}\n{typ=}\n{class_field=}")
    return label_encoded_domain, typ, class_field, idx+4

def parse_dns_questions(packet, num_questions):
    """
    Parses all DNS questions from the packet.

    Args:
        packet (bytes): The full DNS packet.
        num_questions (int): The number of questions to parse.

    Returns:
        tuple: (questions, next_index)
            questions (list): List of tuples (label_encoded_domain, type, class_field) for each question.
            next_index (int): The index just after the end of the question section.
    """
    """
    Return all parsed questions as domain, type, class tuples of each question.
    also return the index of byte just after the question section ends.
    """
    questions = []
    # exclude 12 bytes of header
    idx = 12
    for _ in range(num_questions):
        print(f"At question num {_}")
        label_encoded_domain, typ, class_field, idx = parse_dns_question(packet, idx)
        questions.append((label_encoded_domain, typ, class_field))
    return questions, idx

def generate_question(label_encoded_domain=CODECRAFTERS_DOMAIN_LABEL_ENCODED):
    """
    Generates a DNS question section for the given label-encoded domain.

    Args:
        label_encoded_domain (bytes): The label-encoded domain name.

    Returns:
        bytes: The DNS question section as bytes.
    """
    # name follows label encoding: [6]google[3]com followed by a null byte b'\x00'.
    name = label_encoded_domain
    # corresponding to the "A" record type)
    typ = int(1).to_bytes(2)
    # (corresponding to the "IN" record class)
    class_field = int(1).to_bytes(2)
    return name + typ + class_field

def generate_answer(label_encoded_domain=CODECRAFTERS_DOMAIN_LABEL_ENCODED):
    """
    Generates a DNS answer section for the given label-encoded domain.

    Args:
        label_encoded_domain (bytes): The label-encoded domain name.

    Returns:
        bytes: The DNS answer section as bytes, including the IP address (8.8.8.8 by default).
    """
    name = label_encoded_domain
    # corresponding to the "A" record type)
    typ = int(1).to_bytes(2)
    # (corresponding to the "IN" record class)
    class_field = int(1).to_bytes(2)
    # This field tells the client how much time the name->IP mapping is valid for.
    time_to_live = int(60).to_bytes(4)
    # Length 4, encoded as a 2-byte big-endian int (corresponds to the length of the RDATA field)
    length_rdata = int(4).to_bytes(2)
    # Data	Any IP address, encoded as a 4-byte big-endian int.
    # For example: \x08\x08\x08\x08\ (that's 8.8.8.8 encoded as a 4-byte integer)
    ip = b'\x08\x08\x08\x08'
    return name + typ + class_field + time_to_live + length_rdata + ip


def forward_and_get_answers(recvd_header_dict, received_questions, udp_socket, address, packets_buffer):
    """
    Forwards DNS questions to an upstream DNS server and collects the answers.

    Args:
        recvd_header_dict (dict): The parsed header of the received DNS packet.
        received_questions (list): List of questions to forward.
        udp_socket (socket.socket): The UDP socket to use for communication.
        address (str): The address of the upstream DNS server (format: 'ip:port').
        packets_buffer (list): Buffer to store unrelated packets for later processing.

    Returns:
        bytes: Concatenated answer sections from the upstream DNS server.
    """
    """
    Idea is that if my dns server doesn't have the ip,
    it will ask another DNS server and respond back to the client.

    We have to forward each question separately and concatenate their answers together and return that as the
    response answer to the client. (This is kind of a shortcut, normally, we would first check in our cache first,
    and only if we don't have the corresponding IP, we would reach out to the forwarding server).

    Note:
        This function is bad.
        It returns a value, it also mutates the packets_buffer param.
    """
    ip, port = tuple(address.split(':'))
    peer = ip, int(port)
    print(f"peer is {peer}")
    concat_answer = b''

    packet_id = recvd_header_dict["Packet ID"]
    opcode = recvd_header_dict["Opcode"]
    rd = recvd_header_dict["RD"]
    rcode = recvd_header_dict["RCODE"]
    qr = recvd_header_dict['QR']

    # 1. Generate a header for a request to forwarding server with 1 question count.
    header_to_forward = generate_dns_header(question_count=1, answer_count=0, packet_id=packet_id,
                                          opcode=opcode, rd=rd, response_code=rcode, qr=qr)

    # 2. For each client question, send a request to forwarding server.
    # Then we listen for packets. Some packets received might be requests from other clients, make sure to buffer them
    # and keep them for later processing.
    for q in received_questions:
        domain = q[0]
        q_bytes = generate_question(domain)
        packet_to_forward = header_to_forward + q_bytes
        # Send packet to FORWARDING_SERVER
        udp_socket.sendto(packet_to_forward, peer)
        while True:
            # Wait for packet from FORWARDING_SERVER, if packet is from elsewhere. Buffer it for later processing.
            buf, source = udp_socket.recvfrom(512)
            print(f"{source=}")
            print(f"expected_source={peer}")
            if source != peer:
                # this is a request from another client. Just add it to the packets.
                packets_buffer.append((buf, source))
            else:
                break
        print(f"{packets_buffer=}")
        # Ensure this is indeed the reponsse packet from FORWARDING_SERVER.
        assert source == peer
        answer_bytes = buf[len(packet_to_forward):]
        concat_answer += answer_bytes

    return concat_answer


def get_args():
    """
    Parses command-line arguments for the DNS server.

    Returns:
        argparse.Namespace: The parsed arguments, including the optional resolver address.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--resolver', type=str,
                        help='forward to this dns server when my dns server doesnt have the answer')
    return parser.parse_args()


def main():
    """
    Main entry point for the DNS server. Handles incoming DNS requests, processes them, and sends responses.
    Supports forwarding to an upstream resolver if specified.
    """
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    args = get_args()


    # My UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    # Since we are using same socket for receiving IP queries from clients and
    # also IP responses from forwarded DNS servers. They may come in any order.
    # We have to store the packets here so that we can check for what we need and keep the rest to handle later.
    packets_buffer = []

    while True:
        try:
            # Receives 512 bytes (at most)
            # Conventionally, DNS packets are sent using UDP transport and are limited to 512 bytes.

            # If there is a pending packet in packets buffer, process that first.
            if not packets_buffer:
                buf, source = udp_socket.recvfrom(512)
            else:
                buf, source = packets_buffer[0]
                packets_buffer = packets_buffer[1:]

            print(f"data in {buf=}\n buf_len = {len(buf)}")
            recvd_header_dict = parse_dns_header(buf)
            packet_id = recvd_header_dict["Packet ID"]
            opcode = recvd_header_dict["Opcode"]
            rd = recvd_header_dict["RD"]
            qdcount = recvd_header_dict["QDCOUNT"]

            # 1. create response header
            # Response Code (RCODE)
            # 0 (no error) if OPCODE is 0 (standard query) else 4 (not implemented)
            rcode = 0 if opcode == 0 else 4
            response_header = generate_dns_header(question_count=qdcount, answer_count=qdcount, packet_id=packet_id,
                                         opcode=opcode, rd=rd, response_code=rcode)

            # 2. parse questions
            questions, question_section_end = parse_dns_questions(buf, qdcount)
            print(f"Questions received:\n {questions=}")
            # The question is also sent to client as it is.
            response_question_section = buf[12:question_section_end]

            # 3. create answer section
            response_answer_section = b''

            # If we have a DNS forwarding server, then ask it for the answer. Else lookup in your own cache.
            if args.resolver:
                print(f"forwarding server at : {args.resolver}")
                response_answer_section = forward_and_get_answers(recvd_header_dict, questions,
                                                                  udp_socket, args.resolver, packets_buffer)
            else:
                for question in questions:
                    label_encoded_domain, _, _ = question
                    answer = generate_answer(label_encoded_domain=label_encoded_domain)
                    response_answer_section += answer
            response = response_header + response_question_section + response_answer_section
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
