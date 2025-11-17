"""
Public Key Authority (PKA)
===========================
Trusted third party yang menyimpan dan mendistribusikan public key

Fungsi:
- Menyimpan database public key dari semua client
- Memberikan public key client lain saat diminta
- Mensertifikasi public key (trusted authority)
"""

import socket
import threading
from RSA import generate_keypair

# ==== KONFIGURASI PKA ====
HOST = '0.0.0.0'
PORT = 6000

# Database public key
# Format: {"client_id": (e, n), ...}
public_key_db = {}

# PKA's own key pair untuk signing (opsional, untuk advanced)
pka_public_key, pka_private_key = generate_keypair(1024)

def handle_client(conn, addr):
    """Handle request dari client"""
    try:
        print(f"\n[PKA] Connection from {addr}")
        
        # Terima request
        request = conn.recv(4096).decode()
        parts = request.split('|')
        command = parts[0]
        
        if command == "REGISTER":
            # Format: REGISTER|client_id|e|n
            client_id = parts[1]
            e = int(parts[2])
            n = int(parts[3])
            
            # Simpan public key
            public_key_db[client_id] = (e, n)
            print(f"[PKA] Registered {client_id}")
            print(f"      Public Key: (e={e}, n={len(str(n))} digits)")
            
            # Kirim konfirmasi
            response = "OK|Public key registered"
            conn.send(response.encode())
        
        elif command == "GET_KEY":
            # Format: GET_KEY|client_id
            target_id = parts[1]
            
            if target_id in public_key_db:
                e, n = public_key_db[target_id]
                response = f"OK|{e}|{n}"
                print(f"[PKA] Sent public key of {target_id}")
            else:
                response = "ERROR|Client not found"
                print(f"[PKA] Client {target_id} not found")
            
            conn.send(response.encode())
        
        elif command == "LIST":
            # List semua registered clients
            clients = list(public_key_db.keys())
            response = f"OK|{','.join(clients)}"
            conn.send(response.encode())
            print(f"[PKA] Sent client list: {clients}")
        
        elif command == "GET_PKA_KEY":
            # Kirim public key PKA (untuk verifikasi/signing)
            e, n = pka_public_key
            response = f"OK|{e}|{n}"
            conn.send(response.encode())
            print(f"[PKA] Sent PKA public key")
        
        else:
            response = "ERROR|Unknown command"
            conn.send(response.encode())
    
    except Exception as e:
        print(f"[PKA] Error handling client {addr}: {e}")
    
    finally:
        conn.close()

def start_pka():
    """Start PKA server"""
    print("=" * 60)
    print("PUBLIC KEY AUTHORITY (PKA)")
    print("=" * 60)
    print(f"[PKA] Starting server on {HOST}:{PORT}")
    print(f"[PKA] PKA Public Key:")
    print(f"      e = {pka_public_key[0]}")
    print(f"      n = {len(str(pka_public_key[1]))} digits")
    print("\n[PKA] Waiting for clients...\n")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    
    try:
        while True:
            conn, addr = server.accept()
            # Handle setiap client di thread terpisah
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.daemon = True
            client_thread.start()
    
    except KeyboardInterrupt:
        print("\n[PKA] Shutting down...")
    
    finally:
        server.close()

if __name__ == "__main__":
    start_pka()
