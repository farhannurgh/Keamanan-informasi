# DES implementation

import argparse
import base64
import re

def text_to_hex(text):
    # Note: Konversi string ASCII menjadi representasi hex (tanpa spasi, uppercase).
    return ''.join(f"{ord(c):02X}" for c in text)

def hex_bin(s):
    # Note: Ubah string hex menjadi string bit (4 bit per hex digit).
    mp = {'0': "0000", '1': "0001", '2': "0010", '3': "0011",
          '4': "0100", '5': "0101", '6': "0110", '7': "0111",
          '8': "1000", '9': "1001", 'A': "1010", 'B': "1011",
          'C': "1100", 'D': "1101", 'E': "1110", 'F': "1111"}
    return ''.join(mp[i] for i in s)

def bin_hex(s):
    # Note: Ubah string bit (kelipatan 4) kembali menjadi string hex.
    mp = {"0000": '0', "0001": '1', "0010": '2', "0011": '3',
          "0100": '4', "0101": '5', "0110": '6', "0111": '7',
          "1000": '8', "1001": '9', "1010": 'A', "1011": 'B',
          "1100": 'C', "1101": 'D', "1110": 'E', "1111": 'F'}
    return ''.join(mp[s[i:i + 4]] for i in range(0, len(s), 4))

def bin_dec(binary):
    # Note: Konversi string biner menjadi integer desimal.
    return int(binary, 2)

def dec_bin(num):
    # Note: Konversi integer (0-15) menjadi string biner 4-bit.
    res = bin(num)[2:]
    return res.zfill(4)

def permute(k, arr, n):
    # Note: Terapkan permutasi bit berdasarkan tabel arr (1-based index).
    return ''.join(k[i - 1] for i in arr[:n])

def shift_left(k, nth_shifts):
    # Note: Geser sirkuler string bit ke kiri sebanyak nth_shifts.
    return k[nth_shifts:] + k[:nth_shifts]

def xor(a, b):
    # Note: XOR bitwise antara dua string bit dengan panjang sama.
    return ''.join('0' if a[i] == b[i] else '1' for i in range(len(a)))


# === Tabel DES ===
initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]

perm_choice_1 = [57, 49, 41, 33, 25, 17, 9,
                 1, 58, 50, 42, 34, 26, 18,
                 10, 2, 59, 51, 43, 35, 27,
                 19, 11, 3, 60, 52, 44, 36,
                 63, 55, 47, 39, 31, 23, 15,
                 7, 62, 54, 46, 38, 30, 22,
                 14, 6, 61, 53, 45, 37, 29,
                 21, 13, 5, 28, 20, 12, 4]

perm_choice_2 = [14, 17, 11, 24, 1, 5, 3, 28,
                 15, 6, 21, 10, 23, 19, 12, 4,
                 26, 8, 16, 7, 27, 20, 13, 2,
                 41, 52, 31, 37, 47, 55, 30, 40,
                 51, 45, 33, 48, 44, 49, 39, 56,
                 34, 53, 46, 42, 50, 36, 29, 32]

left_shift_sched = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

e_box_exp = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
             8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
             16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
             24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

p_box_perm = [16, 7, 20, 21, 29, 12, 28, 17,
              1, 15, 23, 26, 5, 18, 31, 10,
              2, 8, 24, 14, 32, 27, 3, 9,
              19, 13, 30, 6, 22, 11, 4, 25]

s_boxes = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

inv_initial_perm = [40, 8, 48, 16, 56, 24, 64, 32,
                    39, 7, 47, 15, 55, 23, 63, 31,
                    38, 6, 46, 14, 54, 22, 62, 30,
                    37, 5, 45, 13, 53, 21, 61, 29,
                    36, 4, 44, 12, 52, 20, 60, 28,
                    35, 3, 43, 11, 51, 19, 59, 27,
                    34, 2, 42, 10, 50, 18, 58, 26,
                    33, 1, 41, 9, 49, 17, 57, 25]


# === Proses Enkripsi per blok ===
def encrypt(pt, rkb):
    # Note: Enkripsi satu block 64-bit (input hex 16-nibble) dengan daftar round-key rkb.
    pt = hex_bin(pt)
    pt = permute(pt, initial_perm, 64)
    left = pt[:32]
    right = pt[32:]

    for i in range(16):
        right_exp = permute(right, e_box_exp, 48)
        xor_x = xor(right_exp, rkb[i])

        sbox_str = ""
        for j in range(8):
            row = bin_dec(xor_x[j * 6] + xor_x[j * 6 + 5])
            col = bin_dec(xor_x[j * 6 + 1:j * 6 + 5])
            val = s_boxes[j][row][col]
            sbox_str += dec_bin(val)

        sbox_str = permute(sbox_str, p_box_perm, 32)
        result = xor(left, sbox_str)
        left = result

        if i != 15:
            left, right = right, left

    combine = left + right
    cipher_text = permute(combine, inv_initial_perm, 64)
    return cipher_text


# === MAIN PROGRAM ===
if __name__ == "__main__":
    plaintext = "Keamanan Informasi B"
    print(f"Plaintext: {plaintext}")
    # default key (ASCII)
    key = "RAHASIAK"

    parser = argparse.ArgumentParser(description="Simple DES")
    parser.add_argument('-p', '--plaintext', help='Plaintext untuk dienkripsi')
    args = parser.parse_args()

    if args.plaintext:
        plaintext = args.plaintext

    # Note: Normalisasi key: jika hex literal gunakan itu, jika bukan anggap ASCII dan konversi ke hex.
    def normalize_key(k: str) -> str:
        s = k.strip()
        # if hex literal (allow optional 0x)
        if re.fullmatch(r'(?:0x)?[0-9A-Fa-f]+', s):
            if s.startswith(('0x', '0X')):
                s = s[2:]
            return s.upper()
        # else key ASCII string
        return text_to_hex(s)

    original_key = key
    key_hex = normalize_key(key)
    # Satu DES butuh 16 hex digits (8 bytes)
    if len(key_hex) != 16:
        print(f"Error: normalized key length is {len(key_hex)} hex digits; single-DES expects 16 hex digits (8 bytes).\nNormalized key: {key_hex}")
        raise SystemExit(1)

    # Buat key binary dan round keys
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

    # Tampilkan key
    print(f"\nOriginal key: {original_key}")
    print(f"Key (hex): {key_hex}")
    print("Round keys (hex):")
    for idx, rk in enumerate(rkb, start=1):
        print(f"RK{idx:02d}: {bin_hex(rk)}")

    # --- ENKRIPSI ---
    print("=== ENCRYPTION ===")

    while len(plaintext) % 8 != 0:
        plaintext += ' '

    blocks = [plaintext[i:i+8] for i in range(0, len(plaintext), 8)]
    cipher_total = ""

    for b in blocks:
        hex_pt = text_to_hex(b)
        cipher = bin_hex(encrypt(hex_pt, rkb))
        cipher_total += cipher
        print(f"Plain: {b:<8} → Cipher: {cipher}")

    print("\nCiphertext gabungan (hex):", cipher_total)
    # raw bytes representation
    try:
        raw_bytes = bytes.fromhex(cipher_total)
        print("Ciphertext (raw bytes):", raw_bytes)
        print("Ciphertext (base64):", base64.b64encode(raw_bytes).decode())
    except Exception as e:
        print("(Tidak dapat konversi ke raw bytes):", e)

    # --- DEKRIPSI ---
    print("\n=== DECRYPTION ===")
    rkb_rev = rkb[::-1]
    decrypted = ""

    for i in range(0, len(cipher_total), 16):
        cipher_block = cipher_total[i:i+16]
        plain_block = bin_hex(encrypt(cipher_block, rkb_rev))
        # konversi balik dari hex ke teks
        decrypted += ''.join(chr(int(plain_block[j:j+2], 16)) for j in range(0, len(plain_block), 2))

    print("Hasil Dekripsi :", decrypted.strip())