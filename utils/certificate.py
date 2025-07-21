import random

def build_certificate_payload(config_data):
    required_keys = [
        "server_name",
        "signature_algorithm",
        "valid_from",
        "valid_to",
        "public_key",
        "other_info",
        "curve"
    ]

    # Check for any missing keys
    missing_keys = [key for key in required_keys if key not in config_data]
    if missing_keys:
        raise KeyError(f"Missing required fields in config_data: {', '.join(missing_keys)}")

    # Extract values (safe now since we've validated)
    server_name = config_data["server_name"]
    signature_algorithm = config_data["signature_algorithm"]
    valid_from = config_data["valid_from"]
    valid_to = config_data["valid_to"]
    public_key = config_data["public_key"]
    other_info = config_data["other_info"]
    curve_config = config_data["curve"]

    # Ensure 'name' exists inside curve_config
    if "name" not in curve_config:
        raise KeyError("Missing required field 'name' inside 'curve' config")

    # Build the certificate payload
    certificate_payload = {
        "version": "1.0",
        "type": "ECDSA Self-Signed Certificate",
        "curve": curve_config,
        "subject": {
            "common_name": server_name,
            "public_key": public_key,
            "other_info": other_info
        },
        "issuer": {
            "common_name": server_name
        },
        "signature_algorithm": signature_algorithm,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "serial_number": hex(random.getrandbits(128))  # 128-bit serial number
    }

    return certificate_payload

