import socket
import logging

logging.basicConfig(level=logging.INFO)

def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    # Uncomment this block to pass the first stage

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            # Receives 512 bytes
            buf, source = udp_socket.recvfrom(512)
            logging.info(f"data in {buf=}\n buf_len = {len(buf)}")
            response = b""

            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
