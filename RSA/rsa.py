import math
import secrets
import hashlib


def nsplit(data, splitSize=64):
    if splitSize <= 0:
        raise ValueError("splitSize must be positive")
    if isinstance(data, (bytes, bytearray)):
        buf = bytearray()
        for item in data:
            buf.append(item)
            if len(buf) == splitSize:
                yield bytes(buf)
                buf.clear()
        if len(buf) > 0:
            yield bytes(buf)
        return
    buffer = []
    for item in data:
        buffer.append(item)
        if len(buffer) == splitSize:
            yield buffer
            buffer = []
    if len(buffer) > 0:
        yield buffer

def is_prime(x: int) -> bool:
    start = 2
    ends = int(math.sqrt(x) + 1)
    for i in range(start, ends):
        if x % i == 0:
            return False
    return True

def generate_random_prime(max:int = 1000) -> int:
    limit = 100
    if max < limit:
        raise ValueError(f"Max Value '{max}' is less than {limit}")
    potential_random = secrets.randbelow(max)
    while not is_prime(potential_random):
        potential_random = secrets.randbelow(max)
    return potential_random

def generate_e(phi: int) -> int:
    e = 65537
    while math.gcd(phi, e) != 1:
        e = secrets.randbelow(phi)
    return e

def calculate_d(e: int, phi: int) -> int:
    d = pow(e, -1, phi)
    return d

def generate_keypair(p: int = None, q: int = None) -> tuple[int, int, int]:
    if p is None:
        p = generate_random_prime()
    if q is None:
        q = generate_random_prime()

    N = p * q
    phi = (p - 1) * (q - 1)
    e = generate_e(phi)
    d = calculate_d(e, phi)
    return (N, e, d)

def factorN(N: int) -> tuple[int, int]:
    if N % 2 == 0:
        p = 1
        q = N // 2
        return (p, q)
    lim = int(math.sqrt(N))+1
    for i in range(3, lim, 2):
        if N % i == 0:
            p = i
            q = N // i
            return (p, q)
    raise ValueError("Couldn't factor N")

def privateKeyCracker(N: int, e: int) -> int:
    p, q = factorN(N)
    phi = (p-1) * (q-1)
    d = pow(e, -1, phi)
    return d


class RSA:
    default_size =  1000000

    def __init__(self, public_N: int, public_e: int, private_d: int = None):
        self._N = public_N
        self._e = public_e
        self._d = private_d
        self.block_size = (self._N.bit_length() + 7) // 8

    def encrypt(self, plaintext: bytes) -> bytes:
        return self._encrypt(plaintext, self._e)

    def _encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        pt_numbers = [int.from_bytes(pt_block) for pt_block in nsplit(plaintext, 1)]
        ct_numbers = [pow(num, key, self._N) for num in pt_numbers]
        ciphertext = b"".join([num.to_bytes(self.block_size) for num in ct_numbers])
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self._decrypt(ciphertext, self._d)

    def _decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        if self._d is None:
            raise ValueError("Private key is required for decryption")
        ct_numbers = [int.from_bytes(pt_block) for pt_block in nsplit(ciphertext, self.block_size)]
        pt_numbers = [pow(num, key, self._N) for num in ct_numbers]
        plaintext = b"".join([num.to_bytes(1) for num in pt_numbers])
        return plaintext

    def sign(self, data: bytes) -> bytes:
        if self._d is None:
            raise ValueError("Private key is required to sign")
        hash = hashlib.sha256(data).digest()
        hash_value = [int.from_bytes(hash) for hash in nsplit(hash, 1)]
        signatureInt = [pow(num, self._d, self._N) for num in hash_value]
        signature = b"".join([num.to_bytes(self.block_size) for num in signatureInt])
        return signature

    def verify(self, data: bytes, signature: bytes) -> bytes:
        hash_value  = hashlib.sha256(data).digest()
        signatureInt = [int.from_bytes(signature) for signature in nsplit(signature, self.block_size)]
        signedHashInt = [pow(num, self._e, self._N) for num in signatureInt]
        signed_hash = b"".join([num.to_bytes(1) for num in signedHashInt])
        return hash_value == signed_hash


def HW12bTests():
    print("HW12b Tests:")
    print(generate_keypair())

    # tests to ensure functions work as intended
    N, e, d = generate_keypair()
    rsa = RSA(N, e, d)

    message = b"This is a top secret message, to ensure secure messaging this is a test message"
    # encrypt & decrypt tests
    print(f"\n{message}")
    encryptMSG = rsa.encrypt(message)
    print(f"{encryptMSG}\n")
    decryptMSG = rsa.decrypt(encryptMSG)
    print(decryptMSG)
    print(message == decryptMSG)

    # signature & verification tests
    tamperedMSG = b"This is a top secret message; to ensure secure messaging this is a test message"
    sign1 = rsa.sign(message)
    verifySign1 = rsa.verify(message, sign1)
    verifyTampered = rsa.verify(tamperedMSG, sign1)
    print(f"\n{tamperedMSG}")
    print(f"the signature matches: {verifySign1}")
    print(f"the signature matches: {verifyTampered}")


if __name__ == '__main__':
    HW12bTests()