import socket
from DES import text_to_hex, bin_hex, hex_bin, encrypt
from DES import perm_choice_1, perm_choice_2, left_shift_sched, permute, shift_left

# ==== KONFIGURASI ====
HOST = '192.168.0.151'  # Ganti dengan IP Laptop 2 (Receiver)
PORT = 5000
KEY = "RAHASIAK"

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

# ==== CLIENT SOCKET ====
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
print(f"[Sender] Terhubung ke receiver {HOST}:{PORT}")

while True:
    pesan = input("\n[Sender] Masukkan pesan: ")
    if len(pesan) % 8 != 0:
        pesan += ' ' * (8 - len(pesan) % 8)

    # === ENCRYPT ===
    cipher_total = ""
    for i in range(0, len(pesan), 8):
        hex_pt = text_to_hex(pesan[i:i+8])
        cipher_total += bin_hex(encrypt(hex_pt, rkb))

    s.send(cipher_total.encode())
    print(f"[Sender] Ciphertext terkirim: {cipher_total}")

    # === TERIMA BALASAN ===
    data = s.recv(1024).decode()
    if not data:
        break
    plain_total = ""
    for i in range(0, len(data), 16):
        cipher_block = data[i:i+16]
        plain_block = bin_hex(encrypt(cipher_block, rkb_rev))
        plain_total += ''.join(chr(int(plain_block[j:j+2], 16)) for j in range(0, len(plain_block), 2))
    print(f"[Sender] Balasan (plaintext): {plain_total.strip()}")

s.close()