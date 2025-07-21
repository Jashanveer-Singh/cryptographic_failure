import hashlib
import json
import base64
import re
from .certificate import build_certificate_payload

def find_inverse(number, modulus):
    try:
        return pow(number, -1, modulus)
    except ValueError:
        raise ValueError(f"Modular inverse of {number} modulo {modulus} does not exist.")

def hash_data_to_int(data_string):
    # Ensure the input is a string, then encode it to bytes
    if not isinstance(data_string, str):
        data_string = str(data_string)
    
    # Hash the data using SHA256
    hashed_data = hashlib.sha256(data_string.encode('utf-8')).hexdigest()
    
    # Convert the hexadecimal hash to an integer
    return int(hashed_data, 16)

def hash_certificate_payload_to_int(certificate_payload):
    payload_string = json.dumps(certificate_payload, sort_keys=True, separators=(',', ':'))
    return hash_data_to_int(payload_string)

def to_pem_format(certificate_dict, header="SELF-SIGNED ECDSA CERTIFICATE"):
    json_string = json.dumps(certificate_dict, indent=2)
    base64_bytes = base64.b64encode(json_string.encode('utf-8'))
    base64_string = base64_bytes.decode('utf-8')

    # Format into PEM blocks (64 characters per line)
    pem_lines = [base64_string[i:i+64] for i in range(0, len(base64_string), 64)]
    
    pem_output = f"-----BEGIN {header}-----\n"
    pem_output += "\n".join(pem_lines)
    pem_output += f"\n-----END {header}-----\n"
    return pem_output

def pem_to_dict(certificate_pem):
    pem_pattern = re.compile(r"-----BEGIN.*?-----\s*(.*?)\s*-----END.*?-----", re.DOTALL)
    match = pem_pattern.search(certificate_pem)

    if not match:
        print(f"Error: Invalid PEM format in 'certificate'. Could not find BEGIN/END headers.")
        sys.exit(1)

    base64_string = match.group(1).replace('\n', '')

    try:
        json_bytes = base64.b64decode(base64_string)
        json_string = json_bytes.decode('utf-8')
        return json.loads(json_string)

    except base64.binascii.Error as e:
        print(f"Error: Invalid Base64 content in PEM file '{pem_file_path}': {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Could not decode JSON from Base64 content in '{pem_file_path}'. Data might be corrupted or not valid JSON: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during decoding or JSON parsing: {e}")
        sys.exit(1)


secp256k1 = {
    'name': "secp256k1",
    'a': 0,
    'b': 7,
    'p': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    'n': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    'Gx': 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDb2DCE28D959F2815B16F81798,
    'Gy': 0x483ADA7726A3C4655DA4FBFc0E1108A8FD17B448A68554199C47D08FFB10D4B8,
}

prime256v1 = {
    'name': "prime256v1",
    'a': 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    'b': 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    'p': 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    'n': 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    'Gx': 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    'Gy': 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
}

__all__ = ['find_inverse', 'secp256k1','prime256v1','to_pem_format','build_certificate_payload','hash_certificate_payload_to_int']
