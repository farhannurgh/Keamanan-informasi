import socket
import secrets
from DES import text_to_hex, bin_hex, hex_bin, encrypt
from DES import perm_choice_1, perm_choice_2, left_shift_sched, permute, shift_left
from RSA import generate_keypair, encrypt_des_key, decrypt_des_key

# ==== KONFIGURASI ====
HOST = '0.0.0.0'    # Dengarkan semua interface
PORT = 5000
PKA_HOST = '127.0.0.1'  # IP Public Key Authority
PKA_PORT = 6000
CLIENT_ID = "RECEIVER"

# ==== FUNGSI PKA INTERACTION ====
def register_to_pka(client_id, public_key):
    """Register public key ke PKA"""
    print("\n[Receiver] Registering public key to PKA...")
    try:
        pka = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pka.connect((PKA_HOST, PKA_PORT))
        
        e, n = public_key
        request = f"REGISTER|{client_id}|{e}|{n}"
        pka.send(request.encode())
        
        response = pka.recv(4096).decode()
        if response.startswith("OK"):
            print(f"[Receiver] ✓ Public key registered to PKA")
        else:
            print(f"[Receiver] ✗ Failed to register: {response}")
        
        pka.close()
    except Exception as e:
        print(f"[Receiver] Error connecting to PKA: {e}")

def get_public_key_from_pka(client_id):
    """Ambil public key client lain dari PKA"""
    print(f"\n[Receiver] Requesting public key of '{client_id}' from PKA...")
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
            print(f"[Receiver] ✓ Received public key of '{client_id}'")
            print(f"           e = {e}")
            print(f"           n = {len(str(n))} digits")
            pka.close()
            return (e, n)
        else:
            print(f"[Receiver] ✗ Error: {parts[1]}")
            pka.close()
            return None
    except Exception as e:
        print(f"[Receiver] Error connecting to PKA: {e}")
        return None

# ==== RSA + DES KEY EXCHANGE ====
def rsa_des_receive_key(conn, my_private_key):
    """
    Terima encrypted DES session key dan dekripsi dengan RSA
    Returns: session_key (hex string)
    """
    print("\n[Receiver] === RSA + DES KEY EXCHANGE ===")
    
    # 1. Terima encrypted session key
    encrypted_key_str = conn.recv(4096).decode()
    encrypted_key = int(encrypted_key_str)
    print(f"[Receiver] Received encrypted session key: {len(str(encrypted_key))} digits")
    
    # 2. Dekripsi dengan private key RSA
    print(f"[Receiver] Decrypting session key with my private key...")
    session_key_hex = decrypt_des_key(encrypted_key, my_private_key)
    print(f"[Receiver] Decrypted DES session key: {session_key_hex}")
    print(f"[Receiver] ✓ Key exchange berhasil!\n")
    
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
print("RECEIVER - RSA + DES SECURE COMMUNICATION")
print("=" * 70)

# === STEP 1: Generate RSA Key Pair ===
print("\n=== STEP 1: Generate RSA Key Pair ===")
my_public_key, my_private_key = generate_keypair(1024)
print(f"[Receiver] My Public Key: (e={my_public_key[0]}, n={len(str(my_public_key[1]))} digits)")
print(f"[Receiver] My Private Key: (d={len(str(my_private_key[0]))} digits, n={len(str(my_private_key[1]))} digits)")

# === STEP 2: Register to PKA ===
print("\n=== STEP 2: Register to Public Key Authority ===")
register_to_pka(CLIENT_ID, my_public_key)

# === STEP 3: Setup Server Socket ===
print("\n=== STEP 3: Setup Server Socket ===")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)
print(f"[Receiver] Listening on port {PORT}...")

conn, addr = s.accept()
print(f"[Receiver] ✓ Connected from {addr}")

# === STEP 4: RSA + DES Key Exchange ===
print("\n=== STEP 4: RSA + DES Key Exchange ===")
session_key = rsa_des_receive_key(conn, my_private_key)
rkb = generate_round_keys(session_key)
rkb_rev = rkb[::-1]

print("\n" + "=" * 70)
print("READY FOR SECURE COMMUNICATION")
print("=" * 70)

while True:
    data = conn.recv(1024).decode()
    if not data or data == 'EXIT':
        print("[Receiver] Sender menutup koneksi")
        break

    # Parse plaintext dan ciphertext yang diterima
    parts = data.split('|')
    plain_asli = parts[0]
    cipher_received = parts[1]

    print(f"\n[Receiver] Ciphertext diterima: {cipher_received}")

    # === DECRYPT ===
    plain_total = ""
    for i in range(0, len(cipher_received), 16):
        cipher_block = cipher_received[i:i+16]
        plain_block = bin_hex(encrypt(cipher_block, rkb_rev))
        plain_total += ''.join(chr(int(plain_block[j:j+2], 16)) for j in range(0, len(plain_block), 2))

    print(f"[Receiver] Plaintext asli dari sender: {plain_asli.strip()}")
    print(f"[Receiver] Hasil Dekripsi: {plain_total.strip()}")
    print(f"[Receiver] Konfirmasi: {'✓ COCOK' if plain_asli.strip() == plain_total.strip() else '✗ TIDAK COCOK'}")

    # === BALAS PESAN ===
    balasan = input("\n[Receiver] Masukkan pesan balasan (ketik 'exit' untuk keluar): ")
    
    if balasan.lower() == 'exit':
        conn.send(b'EXIT')
        print("[Receiver] Menutup koneksi...")
        break
    
    if len(balasan) % 8 != 0:
        balasan += ' ' * (8 - len(balasan) % 8)
    cipher_reply = ""
    for i in range(0, len(balasan), 8):
        hex_pt = text_to_hex(balasan[i:i+8])
        cipher_reply += bin_hex(encrypt(hex_pt, rkb))

    # Kirim plaintext dan ciphertext (dipisah dengan '|')
    message_reply = f"{balasan}|{cipher_reply}"
    conn.send(message_reply.encode())
    print(f"[Receiver] Plaintext: {balasan}")
    print("[Receiver] Ciphertext balasan dikirim.")

conn.close()
