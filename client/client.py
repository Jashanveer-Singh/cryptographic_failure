import socket
import hashlib
import os
import sys
import base64
import json
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'ecc')))

from ecdsa import ECDSA
from ecc_utils import Point, get_curve
from utils import prime256v1, secp256k1, hash_data_to_int, hash_certificate_payload_to_int, pem_to_dict

HOST = '127.0.0.1'
DEFAULT_PORT = 8080
SAFE_MODE = False

def setup_client_socket(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"Connecting to {HOST}:{port}...")
        s.connect((HOST, port))
        return s
    except socket.error as e:
        print(f"ERROR: Could not connect to server at {HOST}:{port}.\n{e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Unexpected error occurred during client setup/connection.\n{e}", file=sys.stderr)
        sys.exit(1)

def recieve_certificate(client_socket):
    try:
        message = "Hello from the Python client! Request certificate."
        client_socket.sendall(message.encode('utf-8'))
        print(f"Sent: {message}")

        data = client_socket.recv(2048)

        print("Received certificate.\n")
        return data.decode('utf-8')
    except socket.error as e:
        print(f"ERROR: Socket error during send/receive.\n{e}", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred during message exchange.\n{e}", file=sys.stderr)

def is_valid_curve_vulnerable(curve):

    try:
        verify_curve_with = get_curve(curve.get('name'))
    except:
        return False

    for key, expected_value in verify_curve_with.items():
        if key in ('Gx', 'Gy'):
            continue  # Skip base point check (vulnerable design)

        if curve.get(key) != expected_value:
            return False

    return True

def is_valid_curve(curve):
    try:
        verify_curve_with = get_curve(curve.get('name'))
    except:
        return False
    for key, expected_value in verify_curve_with.items():
        if curve.get(key) != expected_value:
            return False
    return True

def get_curve_from_certificate(certificate_data):
    given_curve = {}
    for key, value in certificate_data['payload']['curve'].items():
        if key == "name":
            given_curve[key] = value
        elif isinstance(value, str) and value.startswith("0x"):
            given_curve[key] = int(value, 16)
        else:
            given_curve[key] = value  # Already an int
    return given_curve

def is_valid_signed_certificate(certificate,public_key,ecdsa_instance):
    payload_hash_int = hash_certificate_payload_to_int(certificate['payload'])


    r = int(certificate['signature']['r'], 16)
    s = int(certificate['signature']['s'], 16)
    signature = (r, s)

    return ecdsa_instance.verify(signature, payload_hash_int, public_key)

def verify_certificate(certificate_pem, public_key, safe_mode):
    certificate = pem_to_dict(certificate_pem)

    validator = is_valid_curve if safe_mode else is_valid_curve_vulnerable

    curve_in_certificate = get_curve_from_certificate(certificate)
    if not validator(curve_in_certificate):
        print(f"ERROR:this should be bypassed Unknown curve. Verifcation Failed")
        return
    ecdsa_instance = ECDSA(curve_in_certificate)
    public_key_point = Point(public_key['x'], public_key['y'])


    if is_valid_signed_certificate(certificate, public_key_point, ecdsa_instance):
        print("Certificate verification successful! The certificate is valid.")
    else:
        print(f"ERROR: Unknown curve. Verifcation Failed")

def run_client(port=8080, safe_mode=False):
    try:
        global public_key
        with open('public_key.json', 'r') as f:
            public_key_json = f.read().encode('utf-8')
            public_key = json.loads(public_key_json)

        with setup_client_socket(port) as client_socket:
            print("Connected.")
            certificate_pem = recieve_certificate(client_socket)
            verify_certificate(certificate_pem, public_key, safe_mode)

        print("Client finished, connection closed.")
    except Exception as e:
        print(f"ERROR: Unexpected error.\n{e}", file=sys.stderr)

if __name__ == "__main__":
    port = DEFAULT_PORT
    safe_mode = False

    if len(sys.argv) >= 2:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print("ERROR: Invalid port number. Using default.")
            port = DEFAULT_PORT

    if len(sys.argv) >= 3 and sys.argv[2] == "-s":
        safe_mode = True
        print("Safe mode enabled.")

    run_client(port, safe_mode)
