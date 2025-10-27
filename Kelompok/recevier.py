import socket
from DES import text_to_hex, bin_hex, hex_bin, encrypt
from DES import perm_choice_1, perm_choice_2, left_shift_sched, permute, shift_left

# ==== KONFIGURASI ====
HOST = '0.0.0.0'    # Dengarkan semua interface
PORT = 5000
KEY = "RAHASIAK"     # Key yang sama digunakan di sender

# ==== FUNGSI BUAT ROUND KEY ====
def generate_round_keys(key_str):
    key_hex = ''.join(f"{ord(c):02X}" for c in key_str)
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

rkb = generate_round_keys(KEY)
rkb_rev = rkb[::-1]

# ==== SETUP SERVER SOCKET ====
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)
print(f"[Receiver] Listening on port {PORT}...")

conn, addr = s.accept()
print(f"[Receiver] Connected from {addr}")

while True:
    data = conn.recv(1024).decode()
    if not data:
        break

    print(f"\n[Receiver] Ciphertext diterima: {data}")

    # === DECRYPT ===
    plain_total = ""
    for i in range(0, len(data), 16):
        cipher_block = data[i:i+16]
        plain_block = bin_hex(encrypt(cipher_block, rkb_rev))
        plain_total += ''.join(chr(int(plain_block[j:j+2], 16)) for j in range(0, len(plain_block), 2))

    print(f"[Receiver] Hasil Dekripsi: {plain_total.strip()}")

    # === BALAS PESAN ===
    balasan = input("[Receiver] Masukkan pesan balasan: ")
    if len(balasan) % 8 != 0:
        balasan += ' ' * (8 - len(balasan) % 8)
    cipher_reply = ""
    for i in range(0, len(balasan), 8):
        hex_pt = text_to_hex(balasan[i:i+8])
        cipher_reply += bin_hex(encrypt(hex_pt, rkb))

    conn.send(cipher_reply.encode())
    print("[Receiver] Ciphertext balasan dikirim.")

conn.close()
