import random
import hashlib
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils import find_inverse, secp256k1, prime256v1
from ecc_utils import Ecc

class ECDSA:
    def __init__(self, curve_config):

        self.ecc = Ecc(**curve_config)
        self.n = self.ecc.n
        self.G = self.ecc.G

    def generate_key_pair(self):
        private_key = random.randint(1, self.n - 1)

        public_key = self.ecc.multiply(self.G, private_key)

        if not self.ecc.is_valid_point(public_key):
            raise ValueError(f"Generated public key {public_key} is not on curve {self.ecc.name}. This indicates an issue with key generation or curve parameters.")

        return private_key, public_key

    def sign(self, message_hash_int, private_key_scalar):
        if not (1 <= private_key_scalar < self.n):
            raise ValueError(f"Private key {private_key_scalar} is out of valid range [1, {self.n-1}] for curve {self.ecc.name}.")

        while True:
            k = random.randint(1, self.n - 1) 
            r_point = self.ecc.multiply(self.G, k)

            r = r_point.x % self.n if r_point.x is not None else 0

            if r == 0:
                sys.stderr.write(f"Warning: r was 0, regenerating k for signature.\n")
                continue

            try:
                k_inverse = find_inverse(k, self.n)
            except ValueError as e:
                sys.stderr.write(f"Error: {e} during k_inverse calculation. Regenerating k.\n")
                continue

            s = (k_inverse * (message_hash_int + r * private_key_scalar)) % self.n

            if s == 0:
                sys.stderr.write(f"Warning: s was 0, regenerating k for signature.\n")
                continue

            break

        return r, s

    def verify(self, signature, message_hash_int, public_key_point):
        r, s = signature

        if not (1 <= r < self.n) or not (1 <= s < self.n):
            sys.stderr.write(f"Error: Signature components r={r} or s={s} out of valid range [1, {self.n-1}]. Signature invalid.\n")
            return False

        if not self.ecc.is_valid_point(public_key_point):
            sys.stderr.write(f"SECURITY ALERT: Public key point {public_key_point} is NOT on the expected curve '{self.ecc.name}'. Signature invalid.\n")
            return False

        try:
            s_inverse = find_inverse(s, self.n)
        except ValueError as e:
            sys.stderr.write(f"Error: {e} during s_inverse calculation (s={s}). Signature invalid.\n")
            return False

        u1 = (message_hash_int * s_inverse) % self.n

        u2 = (r * s_inverse) % self.n

        point1 = self.ecc.multiply(self.G, u1)
        point2 = self.ecc.multiply(public_key_point, u2)

        x_point = self.ecc.add(point1, point2)

        if x_point.x is None:
            sys.stderr.write(f"Error: Verification point X is Point at Infinity. Signature invalid.\n")
            return False

        return x_point.x == r

# --- Test and Demonstration Section ---
if __name__ == "__main__":
    print("--- ECDSA Implementation Demonstration ---")
    print("This file demonstrates ECDSA signing and verification using custom ECC operations.")
    print("It also includes a critical security check against Invalid Curve Attacks.")

    # --- Setup for secp256k1 Curve ---
    print("\n\n--- Using secp256k1 Curve ---")
    ecc_k1 = Ecc(**secp256k1) # Instantiate the secp256k1 curve
    ecdsa_k1 = ECDSA(secp256k1)                # Create an ECDSA handler for this curve
    print(f"ECDSA initialized for curve: {ecdsa_k1.ecc.name}")

    # 1. Generate Key Pair
    print("\n1. Generating Key Pair...")
    private_key_k1, public_key_k1 = ecdsa_k1.generate_key_pair()
    print(f"   Private Key: {private_key_k1}")
    print(f"   Public Key: {public_key_k1}")
    print(f"   Is Public Key on curve? {ecc_k1.is_valid_point(public_key_k1)}") # Should be True

    # 2. Message to Sign
    original_message = "This is the secret message to be signed by Alice."
    # Simulate hashing the message (SHA-256 for 256-bit hash)
    message_hash_bytes = hashlib.sha256(original_message.encode('utf-8')).digest()
    # Convert hash bytes to an integer. The hash can be larger than 'n',
    # but the operations will implicitly handle it modulo 'n'.
    message_hash_int = int.from_bytes(message_hash_bytes, 'big') 

    print(f"\n2. Message to Sign:")
    print(f"   Original: '{original_message}'")
    print(f"   SHA-256 Hash (int): {message_hash_int}")

    # 3. Sign the Message
    print("\n3. Signing Message (Alice's side)...")
    signature_k1 = ecdsa_k1.sign(message_hash_int, private_key_k1)
    print(f"   Generated Signature (r, s): {signature_k1}")

    # 4. Verify the Signature (Positive Case - Bob's side)
    print("\n4. Verifying Signature (Positive Case - Bob's side)...")
    is_valid_positive = ecdsa_k1.verify(signature_k1, message_hash_int, public_key_k1)
    print(f"   Is signature valid? {is_valid_positive}") # Expected: True

    # 5. Verify the Signature (Negative Case - Tampered Message)
    print("\n5. Verifying Signature (Negative Case - Tampered Message)...")
    tampered_message = "This is a tampered message trying to fool Bob."
    tampered_hash_bytes = hashlib.sha256(tampered_message.encode('utf-8')).digest()
    tampered_hash_int = int.from_bytes(tampered_hash_bytes, 'big')
    
    is_valid_tampered = ecdsa_k1.verify(signature_k1, tampered_hash_int, public_key_k1)
    print(f"   Is signature valid with tampered message? {is_valid_tampered}") # Expected: False

    # 6. Verify the Signature (Negative Case - Wrong Public Key on the SAME curve)
    print("\n6. Verifying Signature (Negative Case - Wrong Public Key)...")
    # Generate a public key from a different private key on the same curve
    _, wrong_public_key_k1 = ecdsa_k1.generate_key_pair()
    
    is_valid_wrong_pubkey = ecdsa_k1.verify(signature_k1, message_hash_int, wrong_public_key_k1)
    print(f"   Is signature valid with wrong public key (same curve)? {is_valid_wrong_pubkey}") # Expected: False


    # --- Setup for the Invalid Curve Attack Scenario ---
    # This is the core of the cryptographic failure you're demonstrating.
    print("\n\n--- Invalid Curve Attack Scenario Setup ---")
    print("Goal: Show how a public key from a *different* curve would be rejected by a robust verifier.")
    print("If the `is_valid_point` check in `verify` were missing, this could be exploited.")

    # 1. Instantiate the P-256 curve (prime256v1)
    ecc_r1 = Ecc(**prime256v1)
    ecdsa_r1 = ECDSA(prime256v1) # Create an ECDSA handler for P-256
    print(f"\nUsing Attacker's Curve: {ecdsa_r1.ecc.name}")

    # 2. Attacker generates a key pair on the P-256 curve
    attacker_private_key_r1, attacker_public_key_r1 = ecdsa_r1.generate_key_pair()
    print(f"   Attacker's Private Key (on P-256): {attacker_private_key_r1}")
    print(f"   Attacker's Public Key (on P-256): {attacker_public_key_r1}")
    print(f"   Is Attacker's Public Key on P-256 curve? {ecc_r1.is_valid_point(attacker_public_key_r1)}") # Expected: True

    # 3. Simulate Alice (using secp256k1) sending her signature to Bob.
    #    Bob (verifier) is *expecting* a public key on secp256k1.
    print(f"\nBob (using {ecdsa_k1.ecc.name}) receives Alice's signature and the Attacker's Public Key.")

    # Try to verify Alice's (secp256k1) signature using the Attacker's (P-256) public key.
    # A robust verifier (like our `ECDSA.verify` method) should catch this!
    print("Attempting to verify Alice's signature with Attacker's Public Key (from a different curve)...")
    is_valid_foreign_pubkey = ecdsa_k1.verify(signature_k1, message_hash_int, attacker_public_key_r1)
    print(f"   Is signature valid with Attacker's foreign public key? {is_valid_foreign_pubkey}") # Expected: False

    print("\nNote the 'SECURITY ALERT' message printed above. This demonstrates the critical importance of validating that the provided public key lies on the *expected* curve.")
    print("If the `is_valid_point` check in `ECDSA.verify` were removed or flawed, this verification could potentially succeed, enabling an invalid curve attack.")

    # Optional: Demonstrate signing/verification directly on P-256
    print("\n\n--- ECDSA using prime256v1 (P-256) for completeness ---")
    message_p256 = "Another message for P-256 curve."
    message_hash_p256_bytes = hashlib.sha256(message_p256.encode('utf-8')).digest()
    message_hash_p256_int = int.from_bytes(message_hash_p256_bytes, 'big')

    signature_r1 = ecdsa_r1.sign(message_hash_p256_int, attacker_private_key_r1)
    print(f"P-256 Signature (r, s): {signature_r1}")
    print(f"P-256 Signature valid: {ecdsa_r1.verify(signature_r1, message_hash_p256_int, attacker_public_key_r1)}")
