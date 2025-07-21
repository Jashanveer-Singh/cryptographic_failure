import socket
import sys

HOST = '0.0.0.0'
PORT = 8081

def setup_server_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"Server listening on {HOST}:{PORT}")
        return s

    except socket.error as e:
        print(f"ERROR: Could not set up server socket.\n{e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Socket setup error.\n{e}", file=sys.stderr)
        sys.exit(1)

def accept_request(server_socket):
    try:
        return server_socket.accept()
    except socket.timeout as e:
        raise e
        # print("ERROR: Accept timed out. No client connected.", file=sys.stderr)
    except socket.error as e:
        print(f"ERROR: Socket error during accept.\n{e}", file=sys.stderr)
    except Exception as e:
        print(f"ERROR: Unexpected error occurred during client accept: {e}", file=sys.stderr)

def handle_client_connection(conn, addr):
    try:
        with conn:
            print(f"Connected by {addr}")
            data = conn.recv(1024)
            if not data:
                print(f"Client {addr} disconnected without sending data.")
                return

            print(f"Received from {addr}: {data.decode('utf-8')}")

            conn.sendall(certificate_pem)
            print(f"Echoed certificate to {addr}.")
    except socket.error as e:
        print(f"ERROR: Socket error during connection with client: {addr}.\n{e}", file=sys.stderr)
    except Exception as e:
        print(f"ERROR: Unexpected error during handling client: {addr}.\n{e}",file=sys.stderr)

def run_server():
    try:
        global certificate_pem
        with open('malicious_certificate.pem', 'r') as f:
            certificate_pem = f.read().encode('utf-8')

        with setup_server_socket() as server_socket:
            print("Waiting for a client connection...")
            while True:
                client_conn, client_addr = accept_request(server_socket)
                handle_client_connection(client_conn, client_addr)

        print("shuting down")

    except FileNotFoundError:
        print("Error: PEM file not found at 'malicious_certificate.pem'", file=sys.stderr)
        sys.exit(1)


    except Exception as e:
        print(f"Server Error: {e}", file=sys.stderr)


if __name__ == "__main__":
    run_server()
