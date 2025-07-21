import json
import os
import sys
import hashlib
import base64

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..' )))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'ecc')))

from ecdsa import ECDSA
from utils import to_pem_format, hash_data_to_int, pem_to_dict, hash_certificate_payload_to_int

# def hash_data_to_int(data_string):
#     # ensure the input is a string, then encode it to bytes
#     if not isinstance(data_string, str):
#         data_string = str(data_string)
#
#     # hash the data using sha256
#     hashed_data = hashlib.sha256(data_string.encode('utf-8')).hexdigest()
#
#     # convert the hexadecimal hash to an integer
#     return int(hashed_data, 16)


def generate_malicious_certificate(original_certificate_payload, public_key):
    malicious_certificate = original_certificate_payload
    malicious_certificate['curve']['Gx'] = public_key['x']
    malicious_certificate['curve']['Gy'] = public_key['y']
    return malicious_certificate

def build_signed_certificate(certificate_payload, private_key, ecdsa_instance):
    payload_hash_int = hash_certificate_payload_to_int(certificate_payload)
    r, s = ecdsa_instance.sign(payload_hash_int, private_key)
    certificate_signature = {"r": hex(r), "s": hex(s)}

    return {
        "payload": certificate_payload,
        "signature": certificate_signature
    }

def get_curve_from_certificate(certificate_data):
    given_curve = {}
    for key, value in certificate_data['curve'].items():
        if key == "name":
            given_curve[key] = value
        elif isinstance(value, str) and value.startswith("0x"):
            given_curve[key] = int(value, 16)
        else:
            given_curve[key] = value  # Already an int
    return given_curve

def sign_certificate(malicious_certificate):


    # given_curve = {}
    # for key, value in malicious_certificate['curve'].items():
    #     if key == "name":
    #         given_curve[key] = value
    #     elif isinstance(value, str) and value.startswith("0x"):
    #         given_curve[key] = int(value, 16)
    #     else:
    #         given_curve[key] = value  # already an int
    # print(given_curve)
    ecdsa_instance = ECDSA(get_curve_from_certificate(malicious_certificate))

    signed_malicious_certificate = build_signed_certificate(malicious_certificate, 1, ecdsa_instance)
    # payload_string = json.dumps(malicious_certificate, sort_keys=True, separators=(',', ':'))
    # payload_hash_int = hash_data_to_int(payload_string)
    #
    # r, s = ecdsa_instance.sign(payload_hash_int, 1)
    # certificate_signature = {"r": hex(r), "s": hex(s)}
    #
    # signed_malicious_certificate = {
    #     "payload": malicious_certificate,
    #     "signature": certificate_signature
    # }

    return to_pem_format(signed_malicious_certificate)

# def to_pem_format(certificate_dict, header="self-signed ecdsa certificate"):
#     """
#     converts a certificate dictionary to a simplified pem format.
#     the entire json representation of the certificate is base64 encoded.
#     """
#     json_string = json.dumps(certificate_dict, indent=2)
#     base64_bytes = base64.b64encode(json_string.encode('utf-8'))
#     base64_string = base64_bytes.decode('utf-8')
#
#     # format into pem blocks (64 characters per line)
#     pem_lines = [base64_string[i:i+64] for i in range(0, len(base64_string), 64)]
#
#     pem_output = f"-----begin {header}-----\n"
#     pem_output += "\n".join(pem_lines)
#     pem_output += f"\n-----end {header}-----\n"
#     return pem_output

if __name__ == "__main__":
    with open('original_certificate.pem', 'r') as f:
        original_certificate_pem = f.read().encode('utf-8').decode('utf-8')
        original_certificate = pem_to_dict(original_certificate_pem)

    with open('public_key.json', 'r') as f:
        public_key_json = f.read().encode('utf-8')
        public_key = json.loads(public_key_json)

    malicious_certificate = generate_malicious_certificate(original_certificate['payload'], public_key)
    signed_malicious_certificate_pem = sign_certificate(malicious_certificate)

    with open('malicious_certificate.pem', 'w') as f:
        f.write(signed_malicious_certificate_pem)
    print(f"\nmalicious certificate (pem) saved to 'malicious_certificate.pem'")

