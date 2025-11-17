"""
RSA Implementation from Scratch
================================
Implementasi RSA tanpa library eksternal untuk Public Key Distribution
"""

import random
import math

# ==== FUNGSI UTILITAS ====

def gcd(a, b):
    """Greatest Common Divisor menggunakan algoritma Euclid"""
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    """
    Mencari modular multiplicative inverse menggunakan Extended Euclidean Algorithm
    Cari d sehingga: (e * d) mod phi = 1
    """
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y
    
    _, x, _ = extended_gcd(e, phi)
    return (x % phi + phi) % phi

def is_prime(n, k=5):
    """
    Miller-Rabin primality test
    k = number of rounds (higher = more accurate)
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True

def generate_prime(bits=512):
    """Generate random prime number dengan panjang tertentu (dalam bits)"""
    while True:
        # Generate random odd number
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1  # Set MSB dan LSB ke 1
        
        if is_prime(n):
            return n

# ==== RSA KEY GENERATION ====

def generate_keypair(bits=1024):
    """
    Generate RSA key pair
    Returns: (public_key, private_key)
    - public_key = (e, n)
    - private_key = (d, n)
    """
    print(f"[RSA] Generating {bits}-bit RSA key pair...")
    
    # 1. Generate dua bilangan prima p dan q
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    
    # Pastikan p != q
    while p == q:
        q = generate_prime(bits // 2)
    
    print(f"[RSA] Prime p: {len(bin(p))-2} bits")
    print(f"[RSA] Prime q: {len(bin(q))-2} bits")
    
    # 2. Hitung n = p * q
    n = p * q
    print(f"[RSA] Modulus n: {len(bin(n))-2} bits")
    
    # 3. Hitung φ(n) = (p-1)(q-1)
    phi = (p - 1) * (q - 1)
    
    # 4. Pilih e (public exponent)
    # Umumnya gunakan 65537 (0x10001) karena efisien dan aman
    e = 65537
    
    # Pastikan gcd(e, phi) = 1
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    
    print(f"[RSA] Public exponent e: {e}")
    
    # 5. Hitung d (private exponent)
    # d adalah modular inverse dari e mod phi
    # d * e ≡ 1 (mod phi)
    d = mod_inverse(e, phi)
    print(f"[RSA] Private exponent d: {len(str(d))} digits")
    
    # Public key: (e, n)
    # Private key: (d, n)
    public_key = (e, n)
    private_key = (d, n)
    
    print("[RSA] ✓ Key pair generated!\n")
    
    return public_key, private_key

# ==== RSA ENCRYPTION/DECRYPTION ====

def rsa_encrypt(plaintext, public_key):
    """
    Enkripsi menggunakan RSA
    plaintext: integer atau bytes
    public_key: (e, n)
    Returns: ciphertext (integer)
    """
    e, n = public_key
    
    # Jika input bytes, konversi ke integer
    if isinstance(plaintext, bytes):
        plaintext = int.from_bytes(plaintext, 'big')
    
    # Enkripsi: c = m^e mod n
    ciphertext = pow(plaintext, e, n)
    
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    """
    Dekripsi menggunakan RSA
    ciphertext: integer
    private_key: (d, n)
    Returns: plaintext (integer)
    """
    d, n = private_key
    
    # Dekripsi: m = c^d mod n
    plaintext = pow(ciphertext, d, n)
    
    return plaintext

# ==== FUNGSI HELPER UNTUK DES KEY ====

def encrypt_des_key(des_key_hex, public_key):
    """
    Enkripsi DES key (16 hex chars = 8 bytes) dengan RSA
    des_key_hex: string hex (contoh: "8B7C6D5E4F3A2B1C")
    public_key: (e, n)
    Returns: ciphertext (integer)
    """
    # Konversi hex string ke bytes
    des_key_bytes = bytes.fromhex(des_key_hex)
    
    # Enkripsi dengan RSA
    ciphertext = rsa_encrypt(des_key_bytes, public_key)
    
    return ciphertext

def decrypt_des_key(ciphertext, private_key):
    """
    Dekripsi DES key dengan RSA
    ciphertext: integer
    private_key: (d, n)
    Returns: des_key_hex (string hex)
    """
    # Dekripsi dengan RSA
    plaintext_int = rsa_decrypt(ciphertext, private_key)
    
    # Konversi integer ke bytes (8 bytes untuk DES)
    des_key_bytes = plaintext_int.to_bytes(8, 'big')
    
    # Konversi ke hex string
    des_key_hex = des_key_bytes.hex().upper()
    
    return des_key_hex

# ==== TESTING ====

if __name__ == "__main__":
    print("=" * 60)
    print("RSA IMPLEMENTATION TEST")
    print("=" * 60)
    
    # Test 1: Key Generation
    print("\n=== TEST 1: Key Generation ===")
    public_key, private_key = generate_keypair(1024)
    e, n = public_key
    d, _ = private_key
    
    print(f"Public Key (e, n):")
    print(f"  e = {e}")
    print(f"  n = {n}")
    print(f"\nPrivate Key (d, n):")
    print(f"  d = {d}")
    print(f"  n = {n}")
    
    # Test 2: Encrypt/Decrypt Message
    print("\n=== TEST 2: Encrypt/Decrypt Simple Message ===")
    message = 12345
    print(f"Original message: {message}")
    
    encrypted = rsa_encrypt(message, public_key)
    print(f"Encrypted: {encrypted}")
    
    decrypted = rsa_decrypt(encrypted, private_key)
    print(f"Decrypted: {decrypted}")
    
    print(f"Match: {message == decrypted} ✓" if message == decrypted else "✗")
    
    # Test 3: Encrypt/Decrypt DES Key
    print("\n=== TEST 3: Encrypt/Decrypt DES Key ===")
    des_key = "8B7C6D5E4F3A2B1C"
    print(f"Original DES key: {des_key}")
    
    encrypted_key = encrypt_des_key(des_key, public_key)
    print(f"Encrypted: {encrypted_key}")
    
    decrypted_key = decrypt_des_key(encrypted_key, private_key)
    print(f"Decrypted: {decrypted_key}")
    
    print(f"Match: {des_key == decrypted_key} ✓" if des_key == decrypted_key else "✗")
    
    print("\n" + "=" * 60)
    print("ALL TESTS PASSED! ✓")
    print("=" * 60)
