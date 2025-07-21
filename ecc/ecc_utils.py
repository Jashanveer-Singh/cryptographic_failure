import random
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils import find_inverse, secp256k1, prime256v1

def get_curve(curve_name):
    if curve_name == "secp256k1":
        return secp256k1
    elif curve_name == "prime256v1":
        return prime256v1
    else:
        raise Execption("ERROR: Unsupported Curve")


class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def is_equal(self, other_point):
        if not isinstance(other_point, Point):
            return False
        return self.x == other_point.x and self.y == other_point.y

    def __str__(self):
        if self.x is None and self.y is None:
            return "Point(Infinity)"
        return f"Point(x=0x{self.x:x}, y=0x{self.y:x})"

    def __repr__(self):
        return self.__str__()


class Ecc:
    def __init__(self, name, a, b, p, n, Gx, Gy):
        self.name = name
        self.a = a
        self.b = b
        self.p = p
        self.n = n

        self.G = Point(Gx, Gy)
        if not self.is_valid_point(self.G):
             raise ValueError(f"Generator point G({Gx}, {Gy}) is not on the curve {name}.")

    def is_valid_point(self, point):
        if not isinstance(point, Point):
            return False
        if point.x is None and point.y is None:
            return True
        return (point.y ** 2) % self.p == (point.x ** 3 + self.a * point.x + self.b) % self.p

    def add(self, point1, point2):
        p = self.p

        # if point's coordinates are None then it is at infinity. return other_point.
        if point1.x is None and point1.y is None:
            return point2
        if point2.x is None and point2.y is None:
            return point1

        # Edge Case
        if point1.x == point2.x and (point1.y + point2.y) % p == 0:
            return Point(None, None)

        if point1.is_equal(point2):
            numerator = (3 * point1.x ** 2 + self.a)
            denominator = (2 * point1.y)

        else:
            numerator = (point2.y - point1.y)
            denominator = (point2.x - point1.x)

        if denominator == 0:
            return Point(None, None)

        slope = (numerator * find_inverse(denominator, p)) % p

        x_r = (slope ** 2 - point1.x - point2.x) % p
        y_r = (slope * (point1.x - x_r) - point1.y) % p

        return Point(x_r, y_r)

    def multiply(self, point, times):
        if times == 0:
            return Point(None, None)

        current_point = point
        result_point = Point(None, None)

        while times > 0:
            if times & 1:
                result_point = self.add(result_point, current_point)

            current_point = self.add(current_point, current_point)
            times >>= 1

        return result_point

# --- Testing / Usage Example ---
if __name__ == "__main__":
    print("--- Testing secp256k1 ECC Operations ---")
    ecc_k1 = Ecc(**secp256k1)
    print(f"Curve: {ecc_k1.name}")
    print(f"Base Point (G): {ecc_k1.G}")
    print(f"Order (n): {ecc_k1.n}")

    # Generate a private key (random scalar)
    private_key_k1 = random.randint(1, ecc_k1.n - 1)
    print(f"Private Key: {private_key_k1}")

    # Calculate public key Q = d * G
    public_key_k1 = ecc_k1.multiply(ecc_k1.G, private_key_k1)
    print(f"Public Key (Q): {public_key_k1}")
    print(f"Is Public Key on curve? {ecc_k1.is_valid_point(public_key_k1)}")

    print("\n--- Testing prime256v1 (P-256) ECC Operations ---")
    ecc_r1 = Ecc(**prime256v1)
    print(f"Curve: {ecc_r1.name}")
    print(f"Base Point (G): {ecc_r1.G}")
    print(f"Order (n): {ecc_r1.n}")

    # Generate a private key for P-256
    private_key_r1 = random.randint(1, ecc_r1.n - 1)
    print(f"Private Key: {private_key_r1}")

    # Calculate public key Q = d * G
    public_key_r1 = ecc_r1.multiply(ecc_r1.G, private_key_r1)
    print(f"Public Key (Q): {public_key_r1}")
    print(f"Is Public Key on curve? {ecc_r1.is_valid_point(public_key_r1)}")

    # Test point addition between two different points on secp256k1
    # Example: G + G = 2G (doubling)
    two_g_by_add = ecc_k1.add(ecc_k1.G, ecc_k1.G)
    two_g_by_multiply = ecc_k1.multiply(ecc_k1.G, 2)
    print(f"\n2G (by add): {two_g_by_add}")
    print(f"2G (by multiply): {two_g_by_multiply}")
    print(f"2G (by add) == 2G (by multiply)? {two_g_by_add.is_equal(two_g_by_multiply)}")

    # Test addition of two distinct points (needs another point)
    # Let's take 2G and add G
    three_g_by_add = ecc_k1.add(two_g_by_add, ecc_k1.G)
    three_g_by_multiply = ecc_k1.multiply(ecc_k1.G, 3)
    print(f"\n3G (by add): {three_g_by_add}")
    print(f"3G (by multiply): {three_g_by_multiply}")
    print(f"3G (by add) == 3G (by multiply)? {three_g_by_add.is_equal(three_g_by_multiply)}")

    # Test point at infinity cases
    print("\n--- Testing Point at Infinity Cases ---")
    inf_point = Point(None, None)
    
    # P + O = P
    test_add_inf1 = ecc_k1.add(ecc_k1.G, inf_point)
    print(f"G + O = {test_add_inf1} (Expected G: {ecc_k1.G.is_equal(test_add_inf1)})")

    # O + P = P
    test_add_inf2 = ecc_k1.add(inf_point, ecc_k1.G)
    print(f"O + G = {test_add_inf2} (Expected G: {ecc_k1.G.is_equal(test_add_inf2)})")

    # P + (-P) = O
    # Find -G for ecc_k1.G
    neg_G = Point(ecc_k1.G.x, (-ecc_k1.G.y) % ecc_k1.p)
    test_add_neg = ecc_k1.add(ecc_k1.G, neg_G)
    print(f"G + (-G) = {test_add_neg} (Expected Infinity: {test_add_neg.x is None and test_add_neg.y is None})")

    # Doubling a point with y=0
    # For secp256k1, no points with y=0 exist (except at infinity).
    # If using a custom curve with a point like (x, 0), doubling it would give infinity.
    # For example, if a curve y^2 = x^3 + x had a point (0,0), doubling (0,0) would yield infinity.
    
    # Multiplying by 0 should yield infinity
    test_mult_zero = ecc_k1.multiply(ecc_k1.G, 0)
    print(f"0 * G = {test_mult_zero} (Expected Infinity: {test_mult_zero.x is None and test_mult_zero.y is None})")
