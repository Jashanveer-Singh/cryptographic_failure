import hashlib
import json
import sys
import os
import random
import base64

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ecc_utils import Ecc, Point, get_curve
from ecdsa import ECDSA
from utils import secp256k1, prime256v1, build_certificate_payload, hash_data_to_int, to_pem_format

def hash_certificate_payload_to_int(certificate_payload):
    payload_string = json.dumps(certificate_payload, sort_keys=True, separators=(',', ':'))
    return hash_data_to_int(payload_string)

def build_signed_certificate(certificate_payload, private_key, ecdsa_instance):
    payload_hash_int = hash_certificate_payload_to_int(certificate_payload)
    r, s = ecdsa_instance.sign(payload_hash_int, private_key)
    certificate_signature = {"r": hex(r), "s": hex(s)}

    return {
        "payload": certificate_payload,
        "signature": certificate_signature
    }

def generate_self_signed_certificate(config_data, ecdsa_instance):
    certificate_payload = build_certificate_payload(config_data)

    signing_private_key, signing_public_key = ecdsa_instance.generate_key_pair()

    payload_hash_int = hash_certificate_payload_to_int(certificate_payload)
    r, s = ecdsa_instance.sign(payload_hash_int, signing_private_key)
    certificate_signature = {"r": hex(r), "s": hex(s)}

    self_signed_certificate = build_signed_certificate(certificate_payload, signing_private_key, ecdsa_instance)

    return self_signed_certificate, signing_public_key

def is_valid_signed_certificate(certificate,public_key,ecdsa_instance):
    payload_hash_int = hash_certificate_payload_to_int(certificate['payload'])


    # Extract signature components
    r = int(certificate['signature']['r'], 16)
    s = int(certificate['signature']['s'], 16)
    signature = (r, s)

    # Verify using the *signing* public key
    return ecdsa_instance.verify(signature, payload_hash_int, public_key)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python generate_server_cert.py <config_file_path> <output_certificate_pem_file_path> <output_public_key_json_file_path>")
        sys.exit(1)

    config_file_path = sys.argv[1]
    output_cert_pem_file_path = sys.argv[2]
    output_public_key_json_file_path = sys.argv[3]

    try:
        with open(config_file_path, 'r') as f:
            config_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: Configuration file not found at '{config_file_path}'")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from '{config_file_path}'. Please check file format.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred while reading the config file: {e}")
        sys.exit(1)

    curve = get_curve(config_data['curve']['name'])

    ecdsa_instance = ECDSA(curve)

    certificate, public_key = generate_self_signed_certificate(config_data, ecdsa_instance)
    print("Certificate Generated")

    if is_valid_signed_certificate(certificate,public_key, ecdsa_instance):
        print("Certificate verification successful! The certificate is valid.")
    else:
        print("Certificate verification FAILED! There might be an issue with generation or verification logic.")
        sys.exit(1)

    certificate_pem_content = to_pem_format(certificate)

    try:
        with open(output_cert_pem_file_path, 'w') as f:
            f.write(certificate_pem_content)
        print(f"\nSelf-signed certificate (PEM) saved to '{output_cert_pem_file_path}'")

    except IOError as e:
        print(f"Error: Could not write certificate to '{output_cert_pem_file_path}': {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred while saving the certificate: {e}")
        sys.exit(1)

    try:
        with open(output_public_key_json_file_path, 'w') as f:
            formated_public_key = {
                "curve_name": config_data["curve"]["name"],
                "x": public_key.x,
                "y": public_key.y
            }
            json.dump(formated_public_key, f, indent=2)
        print(f"Client public key info saved to '{output_public_key_json_file_path}'")

    except IOError as e:
        print(f"Error: Could not write public key to '{output_public_key_json_file_path}': {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred while saving the public key: {e}")
        sys.exit(1)

