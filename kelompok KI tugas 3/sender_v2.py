import socket
import secrets
from DES import text_to_hex, bin_hex, hex_bin, encrypt
from DES import perm_choice_1, perm_choice_2, left_shift_sched, permute, shift_left
from RSA import generate_keypair, encrypt_des_key, decrypt_des_key

# ==== KONFIGURASI ====
RECEIVER_HOST = '10.25.84.232'  # IP Receiver
RECEIVER_PORT = 5000
PKA_HOST = '10.25.84.232'  # IP Public Key Authority
PKA_PORT = 6000
CLIENT_ID = "SENDER"

# ==== FUNGSI PKA INTERACTION ====
def register_to_pka(client_id, public_key):
    """Register public key ke PKA"""
    print("\n[Sender] Registering public key to PKA...")
    try:
        pka = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pka.connect((PKA_HOST, PKA_PORT))
        
        e, n = public_key
        request = f"REGISTER|{client_id}|{e}|{n}"
        pka.send(request.encode())
        
        response = pka.recv(4096).decode()
        if response.startswith("OK"):
            print(f"[Sender] ✓ Public key registered to PKA")
        else:
            print(f"[Sender] ✗ Failed to register: {response}")
        
        pka.close()
    except Exception as e:
        print(f"[Sender] Error connecting to PKA: {e}")

def get_public_key_from_pka(client_id):
    """Ambil public key client lain dari PKA"""
    print(f"\n[Sender] Requesting public key of '{client_id}' from PKA...")
    try:
        pka = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pka.connect((PKA_HOST, PKA_PORT))
        
        request = f"GET_KEY|{client_id}"
        pka.send(request.encode())
        
        response = pka.recv(4096).decode()
        parts = response.split('|')
        
        if parts[0] == "OK":
            e = int(parts[1])
            n = int(parts[2])
            print(f"[Sender] ✓ Received public key of '{client_id}'")
            print(f"         e = {e}")
            print(f"         n = {len(str(n))} digits")
            pka.close()
            return (e, n)
        else:
            print(f"[Sender] ✗ Error: {parts[1]}")
            pka.close()
            return None
    except Exception as e:
        print(f"[Sender] Error connecting to PKA: {e}")
        return None

# ==== RSA + DES KEY EXCHANGE ====
def rsa_des_key_exchange(sock, receiver_public_key, my_private_key):
    """
    Generate DES session key dan kirim terenkripsi dengan RSA
    Returns: session_key (hex string)
    """
    print("\n[Sender] === RSA + DES KEY EXCHANGE ===")
    
    # 1. Generate random DES session key (8 bytes = 64 bit)
    session_key_bytes = secrets.token_bytes(8)
    session_key_hex = session_key_bytes.hex().upper()
    print(f"[Sender] Generated DES session key: {session_key_hex}")
    
    # 2. Enkripsi session key dengan RSA menggunakan public key receiver
    print(f"[Sender] Encrypting session key with receiver's public key...")
    encrypted_key = encrypt_des_key(session_key_hex, receiver_public_key)
    print(f"[Sender] Encrypted session key: {len(str(encrypted_key))} digits")
    
    # 3. Kirim encrypted session key ke receiver
    sock.send(str(encrypted_key).encode())
    print(f"[Sender] ✓ Encrypted session key sent to receiver\n")
    
    return session_key_hex

# ==== FUNGSI BUAT ROUND KEY ====
def generate_round_keys(key_hex):
    """Generate DES round keys dari hex key string"""
    key_bin = hex_bin(key_hex)
    key_bin = permute(key_bin, perm_choice_1, 56)
    left, right = key_bin[:28], key_bin[28:]
    rkb = []
    for i in range(16):
        left = shift_left(left, left_shift_sched[i])
        right = shift_left(right, left_shift_sched[i])
        combine = left + right
        round_key = permute(combine, perm_choice_2, 48)
        rkb.append(round_key)
    return rkb

# ==== MAIN PROGRAM ====
print("=" * 70)
print("SENDER - RSA + DES SECURE COMMUNICATION")
print("=" * 70)

# === STEP 1: Generate RSA Key Pair ===
print("\n=== STEP 1: Generate RSA Key Pair ===")
my_public_key, my_private_key = generate_keypair(1024)
print(f"[Sender] My Public Key: (e={my_public_key[0]}, n={len(str(my_public_key[1]))} digits)")
print(f"[Sender] My Private Key: (d={len(str(my_private_key[0]))} digits, n={len(str(my_private_key[1]))} digits)")

# === STEP 2: Register to PKA ===
print("\n=== STEP 2: Register to Public Key Authority ===")
register_to_pka(CLIENT_ID, my_public_key)

# === STEP 3: Get Receiver's Public Key from PKA ===
print("\n=== STEP 3: Get Receiver's Public Key from PKA ===")
receiver_public_key = get_public_key_from_pka("RECEIVER")
if receiver_public_key is None:
    print("[Sender] ✗ Cannot proceed without receiver's public key")
    print("[Sender] Make sure receiver is registered to PKA first!")
    exit(1)

# === STEP 4: Connect to Receiver ===
print("\n=== STEP 4: Connect to Receiver ===")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RECEIVER_HOST, RECEIVER_PORT))
print(f"[Sender] ✓ Connected to receiver at {RECEIVER_HOST}:{RECEIVER_PORT}")

# === STEP 5: RSA + DES Key Exchange ===
print("\n=== STEP 5: RSA + DES Key Exchange ===")
session_key = rsa_des_key_exchange(s, receiver_public_key, my_private_key)
rkb = generate_round_keys(session_key)
rkb_rev = rkb[::-1]

print("\n" + "=" * 70)
print("READY FOR SECURE COMMUNICATION")
print("=" * 70)

while True:
    pesan = input("\n[Sender] Masukkan pesan (ketik 'exit' untuk keluar): ")
    
    if pesan.lower() == 'exit':
        s.send(b'EXIT')
        print("[Sender] Menutup koneksi...")
        break
    
    if len(pesan) % 8 != 0:
        pesan += ' ' * (8 - len(pesan) % 8)

    # === ENCRYPT ===
    cipher_total = ""
    for i in range(0, len(pesan), 8):
        hex_pt = text_to_hex(pesan[i:i+8])
        cipher_total += bin_hex(encrypt(hex_pt, rkb))

    # Kirim plaintext dan ciphertext (dipisah dengan '|')
    message = f"{pesan}|{cipher_total}"
    s.send(message.encode())
    print(f"[Sender] Plaintext: {pesan}")
    print(f"[Sender] Ciphertext terkirim: {cipher_total}")

    # === TERIMA BALASAN ===
    data = s.recv(1024).decode()
    if not data or data == 'EXIT':
        print("[Sender] Receiver menutup koneksi")
        break
    
    # Parse plaintext dan ciphertext yang diterima
    parts = data.split('|')
    plain_asli = parts[0]
    cipher_received = parts[1]
    
    # Dekripsi untuk konfirmasi
    plain_total = ""
    for i in range(0, len(cipher_received), 16):
        cipher_block = cipher_received[i:i+16]
        plain_block = bin_hex(encrypt(cipher_block, rkb_rev))
        plain_total += ''.join(chr(int(plain_block[j:j+2], 16)) for j in range(0, len(plain_block), 2))
    
    print(f"\n[Sender] Ciphertext balasan diterima: {cipher_received}")
    print(f"[Sender] Plaintext asli dari receiver: {plain_asli.strip()}")
    print(f"[Sender] Hasil dekripsi: {plain_total.strip()}")
    print(f"[Sender] Konfirmasi: {'✓ COCOK' if plain_asli.strip() == plain_total.strip() else '✗ TIDAK COCOK'}")

s.close()
