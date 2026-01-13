import os
import uuid
import sqlite3
import hashlib
import secrets
from datetime import datetime, timezone
from getpass import getpass
import tkinter as tk
from tkinter import filedialog

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# ----------------------------
# Config & paths
# ----------------------------
APP_TITLE = "SecureVault"
DB_PATH = os.path.join("data", "app.db")
STORAGE_DIR = "storage"

os.makedirs("data", exist_ok=True)
os.makedirs(STORAGE_DIR, exist_ok=True)

# ----------------------------
# Helper: password hashing (SHA-256 with salt)
# ----------------------------
def hash_password(password: str) -> str:
    """Hash password with salt using SHA-256"""
    salt = secrets.token_hex(16)
    pw_hash = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}${pw_hash}"

def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash"""
    try:
        salt, pw_hash = stored_hash.split("$")
        check_hash = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
        return check_hash == pw_hash
    except:
        return False

# ----------------------------
# DB helpers
# ----------------------------
def db_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
    con = db_conn()
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        rsa_public_pem TEXT NOT NULL,
        rsa_private_pem_enc BLOB NOT NULL,
        created_at TEXT NOT NULL
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        original_name TEXT NOT NULL,
        stored_name TEXT NOT NULL,
        wrapped_key BLOB NOT NULL,
        mys_key_length INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)

    con.commit()
    con.close()

# ----------------------------
# Crypto: RSA keys
# ----------------------------
def generate_rsa_keypair(password: str) -> tuple:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    priv_pem_enc = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8"))
    )

    return pub_pem, priv_pem_enc

def load_public_key(pub_pem: str):
    return serialization.load_pem_public_key(pub_pem.encode("utf-8"))

def load_private_key(priv_pem_enc: bytes, password: str):
    return serialization.load_pem_private_key(priv_pem_enc, password=password.encode("utf-8"))

def rsa_encrypt(public_key, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(private_key, encrypted_data: bytes) -> bytes:
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ----------------------------
# Hybrid Layer: XOR with random seed
# ----------------------------
def generate_random_seed(length: int = 32) -> bytes:
    """Generate random seed for XOR layer"""
    return secrets.token_bytes(length)

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR data with repeating key (for second encryption layer)"""
    key_len = len(key)
    return bytes([data[i] ^ key[i % key_len] for i in range(len(data))])

# ----------------------------
# Classic Cipher: Myszkowski Transposition (bytes)
# ----------------------------
PAD_BYTE = 0x00  # padding byte

def _mys_ranks(key: str) -> list:
    """Generate ranks for Myszkowski cipher - same char gets same rank"""
    key = "".join([c for c in key.upper() if c.isalnum()])
    if not key:
        raise ValueError("Key Myszkowski kosong/invalid.")
    uniq_sorted = sorted(set(key))
    rank_map = {ch: i for i, ch in enumerate(uniq_sorted)}
    return [rank_map[ch] for ch in key]

def myszkowski_encrypt_bytes(plainbytes: bytes, key: str) -> bytes:
    """Encrypt bytes using Myszkowski Transposition"""
    ranks = _mys_ranks(key)
    ncols = len(ranks)
    if ncols < 2:
        raise ValueError("Key terlalu pendek. Minimal 2 karakter alnum.")

    # Pad to full grid
    rows = (len(plainbytes) + ncols - 1) // ncols
    padded = plainbytes + bytes([PAD_BYTE] * (rows * ncols - len(plainbytes)))

    # Build grid row-wise
    grid = []
    for r in range(rows):
        grid.append(list(padded[r * ncols:(r + 1) * ncols]))

    # Read by Myszkowski rule (same rank = read row by row together)
    out = []
    for rank in sorted(set(ranks)):
        cols = [i for i, rv in enumerate(ranks) if rv == rank]
        if len(cols) == 1:
            c = cols[0]
            for r in range(rows):
                out.append(grid[r][c])
        else:
            for r in range(rows):
                for c in cols:
                    out.append(grid[r][c])

    return bytes(out)

def myszkowski_decrypt_bytes(cipherbytes: bytes, key: str) -> bytes:
    """Decrypt bytes using Myszkowski Transposition"""
    ranks = _mys_ranks(key)
    ncols = len(ranks)
    rows = (len(cipherbytes) + ncols - 1) // ncols

    # Create empty grid
    grid = [[0] * ncols for _ in range(rows)]
    idx = 0

    # Fill following Myszkowski rule
    for rank in sorted(set(ranks)):
        cols = [i for i, rv in enumerate(ranks) if rv == rank]
        if len(cols) == 1:
            c = cols[0]
            for r in range(rows):
                grid[r][c] = cipherbytes[idx]
                idx += 1
        else:
            for r in range(rows):
                for c in cols:
                    grid[r][c] = cipherbytes[idx]
                    idx += 1

    # Read row-wise and strip padding
    plainbytes = bytes([grid[r][c] for r in range(rows) for c in range(ncols)])
    return plainbytes.rstrip(bytes([PAD_BYTE]))

# ----------------------------
# Auth functions
# ----------------------------
def create_user(username: str, password: str) -> tuple:
    username = username.strip()
    if len(username) < 3:
        return False, "Username minimal 3 karakter."
    if len(password) < 6:
        return False, "Password minimal 6 karakter."

    con = db_conn()
    cur = con.cursor()

    cur.execute("SELECT id FROM users WHERE username=?", (username,))
    if cur.fetchone():
        con.close()
        return False, "Username sudah terpakai."

    pub_pem, priv_pem_enc = generate_rsa_keypair(password)
    pw_hash = hash_password(password)
    now = datetime.now(timezone.utc).isoformat()

    cur.execute(
        "INSERT INTO users(username, password_hash, rsa_public_pem, rsa_private_pem_enc, created_at) VALUES(?,?,?,?,?)",
        (username, pw_hash, pub_pem, priv_pem_enc, now)
    )
    con.commit()
    con.close()
    return True, "Akun berhasil dibuat. Silakan login."

def authenticate(username: str, password: str):
    con = db_conn()
    cur = con.cursor()
    cur.execute("SELECT id, password_hash, rsa_public_pem, rsa_private_pem_enc FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    con.close()
    if not row:
        return None, "User tidak ditemukan."

    user_id, pw_hash, pub_pem, priv_pem_enc = row
    if not verify_password(password, pw_hash):
        return None, "Password salah."

    try:
        pub_key = load_public_key(pub_pem)
        priv_key = load_private_key(priv_pem_enc, password)
    except Exception:
        return None, "Gagal membuka key."

    return {
        "user_id": user_id,
        "username": username,
        "pub_key": pub_key,
        "priv_key": priv_key,
    }, ""

# ----------------------------
# File operations
# ----------------------------
def save_encrypted_file(user_id: int, file_path: str, pub_key, classic_key: str) -> tuple:
    """
    Hybrid Encryption: Myszkowski + XOR (RSA-wrapped seed)
    
    Flow:
    1. File → Myszkowski(classic_key) → mys_encrypted
    2. Generate random_seed (32 bytes)
    3. mys_encrypted → XOR(random_seed) → final_encrypted
    4. random_seed → RSA_encrypt(pub_key) → wrapped_seed
    5. Store: final_encrypted file + wrapped_seed in DB
    """
    if not os.path.exists(file_path):
        return False, "File tidak ditemukan."

    original_name = os.path.basename(file_path)
    file_id = str(uuid.uuid4())
    stored_name = f"{user_id}_{file_id}.enc"

    # Read file
    with open(file_path, "rb") as f:
        file_bytes = f.read()

    file_size = len(file_bytes)

    # Layer 1: Encrypt with Myszkowski
    mys_encrypted = myszkowski_encrypt_bytes(file_bytes, classic_key)
    
    # Layer 2: Generate random seed and XOR
    random_seed = generate_random_seed(32)
    final_encrypted = xor_bytes(mys_encrypted, random_seed)

    # Wrap the random seed with RSA (this is what we store)
    wrapped_seed = rsa_encrypt(pub_key, random_seed)

    # Save encrypted file
    path = os.path.join(STORAGE_DIR, stored_name)
    with open(path, "wb") as f:
        f.write(final_encrypted)

    # Store metadata (wrapped_key now stores wrapped_seed)
    con = db_conn()
    cur = con.cursor()
    cur.execute("""
        INSERT INTO files(id, user_id, original_name, stored_name, wrapped_key, mys_key_length, created_at, size_bytes)
        VALUES(?,?,?,?,?,?,?,?)
    """, (
        file_id, user_id, original_name, stored_name, wrapped_seed, len(classic_key),
        datetime.now(timezone.utc).isoformat(), file_size
    ))
    con.commit()
    con.close()

    return True, f"File '{original_name}' berhasil dienkripsi (Hybrid: Myszkowski + RSA)!"

def list_user_files(user_id: int):
    con = db_conn()
    cur = con.cursor()
    cur.execute("""
        SELECT id, original_name, created_at, size_bytes
        FROM files WHERE user_id=?
        ORDER BY created_at DESC
    """, (user_id,))
    rows = cur.fetchall()
    con.close()
    return rows

def list_all_files_public():
    """List all files for public view (without user restriction)"""
    con = db_conn()
    cur = con.cursor()
    cur.execute("""
        SELECT f.id, f.original_name, f.created_at, f.size_bytes, u.username
        FROM files f
        JOIN users u ON f.user_id = u.id
        ORDER BY f.created_at DESC
    """)
    rows = cur.fetchall()
    con.close()
    return rows

def encrypt_display_name(name: str) -> str:
    """Encrypt file name for public display using Base64"""
    import base64
    encoded = base64.b64encode(name.encode('utf-8')).decode('utf-8')
    # Truncate if too long for display
    if len(encoded) > 30:
        return encoded[:27] + "..."
    return encoded

def encrypt_username(username: str) -> str:
    """Encrypt username for public display - show first char + asterisks"""
    if len(username) <= 2:
        return username[0] + "*" * (len(username) - 1)
    return username[0] + "*" * (len(username) - 2) + username[-1]

def load_file_record(file_id: str, user_id: int):
    con = db_conn()
    cur = con.cursor()
    cur.execute("""
        SELECT id, original_name, stored_name, wrapped_key
        FROM files WHERE id=? AND user_id=?
    """, (file_id, user_id))
    row = cur.fetchone()
    con.close()
    return row

def load_file_record_public(file_id: str):
    """Load file record without user restriction (for public download)"""
    con = db_conn()
    cur = con.cursor()
    cur.execute("""
        SELECT f.id, f.original_name, f.stored_name, f.wrapped_key, u.username
        FROM files f
        JOIN users u ON f.user_id = u.id
        WHERE f.id=?
    """, (file_id,))
    row = cur.fetchone()
    con.close()
    return row

def decrypt_file_public(record, sharing_key: str, classic_key: str, output_dir: str) -> tuple:
    """
    Hybrid Decryption for public download (requires sharing_key + classic_key)
    
    Flow:
    1. Convert sharing_key (hex) back to random_seed bytes
    2. final_encrypted XOR random_seed → mys_encrypted
    3. Myszkowski_decrypt(classic_key, mys_encrypted) → original file
    """
    file_id, original_name, stored_name, wrapped_seed, owner_username = record
    path = os.path.join(STORAGE_DIR, stored_name)
    
    if not os.path.exists(path):
        return False, "File terenkripsi tidak ditemukan di server."
    
    # Validate output directory
    if not os.path.isdir(output_dir):
        return False, f"Folder output '{output_dir}' tidak ditemukan. Pastikan folder sudah ada."

    # Convert sharing_key (hex string) back to bytes
    try:
        random_seed = bytes.fromhex(sharing_key)
    except ValueError:
        return False, "Sharing Key tidak valid! Pastikan format hex yang benar."

    # Read encrypted file
    with open(path, "rb") as f:
        final_encrypted = f.read()

    # Layer 2: XOR to get Myszkowski-encrypted data
    mys_encrypted = xor_bytes(final_encrypted, random_seed)
    
    # Layer 1: Decrypt with Myszkowski using classic_key
    try:
        decrypted_bytes = myszkowski_decrypt_bytes(mys_encrypted, classic_key)
    except Exception as e:
        return False, f"Gagal dekripsi: Classic Key mungkin salah atau tidak sesuai."

    # Save decrypted file
    output_path = os.path.join(output_dir, original_name)
    with open(output_path, "wb") as f:
        f.write(decrypted_bytes)

    return True, f"File berhasil didekripsi!\n   📁 Disimpan di: {output_path}"

def decrypt_file(record, priv_key, classic_key: str, output_dir: str) -> tuple:
    """
    Hybrid Decryption for owner (requires RSA private key + classic_key)
    
    Flow:
    1. RSA_decrypt(priv_key, wrapped_seed) → random_seed
    2. final_encrypted XOR random_seed → mys_encrypted
    3. Myszkowski_decrypt(classic_key, mys_encrypted) → original file
    """
    file_id, original_name, stored_name, wrapped_seed = record
    path = os.path.join(STORAGE_DIR, stored_name)
    
    if not os.path.exists(path):
        return False, "File terenkripsi tidak ditemukan."
    
    # Validate output directory
    if not os.path.isdir(output_dir):
        return False, f"Folder output '{output_dir}' tidak ditemukan. Pastikan folder sudah ada."

    # Unwrap the random seed using RSA private key
    try:
        random_seed = rsa_decrypt(priv_key, wrapped_seed)
    except Exception as e:
        return False, f"Gagal membuka RSA key: {e}"

    # Read encrypted file
    with open(path, "rb") as f:
        final_encrypted = f.read()

    # Layer 2: XOR to get Myszkowski-encrypted data
    mys_encrypted = xor_bytes(final_encrypted, random_seed)
    
    # Layer 1: Decrypt with Myszkowski
    try:
        decrypted_bytes = myszkowski_decrypt_bytes(mys_encrypted, classic_key)
    except Exception as e:
        return False, f"Gagal decrypt Myszkowski: {e}"

    # Save decrypted file
    output_path = os.path.join(output_dir, original_name)
    with open(output_path, "wb") as f:
        f.write(decrypted_bytes)

    return True, f"File berhasil didekripsi! Disimpan di: {output_path}"

def delete_file(file_id: str, user_id: int) -> tuple:
    rec = load_file_record(file_id, user_id)
    if not rec:
        return False, "File tidak ditemukan."
    _, _, stored_name, _ = rec
    path = os.path.join(STORAGE_DIR, stored_name)

    con = db_conn()
    cur = con.cursor()
    cur.execute("DELETE FROM files WHERE id=? AND user_id=?", (file_id, user_id))
    con.commit()
    con.close()

    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass

    return True, "File berhasil dihapus."

# ----------------------------
# CLI UI
# ----------------------------
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def safe_input(prompt: str, max_length: int = 100, allow_empty: bool = True, is_password: bool = False) -> str:
    """
    User-friendly input with length validation.
    Shows error and re-prompts if input exceeds limit.
    """
    while True:
        if is_password:
            user_input = getpass(prompt)
        else:
            user_input = input(prompt)
        
        if len(user_input) > max_length:
            print(f"\n⚠️  Input terlalu panjang! Maksimal {max_length} karakter.")
            print(f"   Input Anda: {len(user_input)} karakter. Silakan coba lagi.\n")
            continue
        
        if not allow_empty and not user_input.strip():
            print(f"\n⚠️  Input tidak boleh kosong. Silakan coba lagi.\n")
            continue
        
        return user_input

def print_header():
    print("╔══════════════════════════════════════════╗")
    print("║     🔐 SecureVault - File Storage        ║")
    print("║     Kriptografi: Myszkowski + RSA        ║")
    print("╚══════════════════════════════════════════╝")
    print()

def print_menu_utama():
    print("╔══════════════════════════════════════════╗")
    print("║              MENU UTAMA                  ║")
    print("╠══════════════════════════════════════════╣")
    print("║  1. Register                             ║")
    print("║  2. Login                                ║")
    print("║  3. Lihat File Tersimpan (Publik)        ║")
    print("║  4. Keluar                               ║")
    print("╚══════════════════════════════════════════╝")

def print_menu_user(username: str, classic_key: str):
    key_status = f"'{classic_key[:3]}***'" if classic_key else "(belum diset)"
    print(f"╔══════════════════════════════════════════╗")
    print(f"║  👤 User: {username:<30} ║")
    print(f"║  🔑 Classic Key: {key_status:<23} ║")
    print(f"╠══════════════════════════════════════════╣")
    print(f"║  1. Upload File                          ║")
    print(f"║  2. Lihat File Saya                      ║")
    print(f"║  3. Download File Saya                   ║")
    print(f"║  4. Download File Publik                 ║")
    print(f"║  5. Generate Sharing Key                 ║")
    print(f"║  6. Hapus File                           ║")
    print(f"║  7. Ganti Classic Key                    ║")
    print(f"║  8. Logout                               ║")
    print(f"╚══════════════════════════════════════════╝")

def menu_register():
    print("\n=== REGISTER ===")
    print("(Username: 3-50 karakter, Password: 6-128 karakter)\n")
    username = safe_input("Username: ", max_length=50, allow_empty=False).strip()
    password = safe_input("Password: ", max_length=128, allow_empty=False, is_password=True)
    
    ok, msg = create_user(username, password)
    print(f"\n{'✅' if ok else '❌'} {msg}")
    input("\nTekan Enter untuk melanjutkan...")

def menu_login():
    print("\n=== LOGIN ===")
    username = safe_input("Username: ", max_length=50, allow_empty=False).strip()
    
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        password = safe_input("Password: ", max_length=128, allow_empty=False, is_password=True)
        
        user, msg = authenticate(username, password)
        if user:
            print(f"\n✅ Login berhasil! Selamat datang, {username}!")
            input("\nTekan Enter untuk melanjutkan...")
            return user
        else:
            remaining = max_attempts - attempt
            if remaining > 0:
                print(f"\n❌ {msg}")
                print(f"⚠️  Kesempatan tersisa: {remaining}x lagi\n")
            else:
                print(f"\n❌ {msg}")
                print("🚫 Anda telah gagal login 3 kali. Silakan coba lagi nanti.")
                input("\nTekan Enter untuk melanjutkan...")
                return None
    
    return None

def menu_upload(user: dict, classic_key: str):
    print("\n=== UPLOAD FILE ===")
    if not classic_key:
        print("❌ Classic Key belum diset! Silakan set dulu di menu 5.")
        input("\nTekan Enter untuk melanjutkan...")
        return

    print("\nPilih cara input file:")
    print("  1. Browse file (buka dialog)")
    print("  2. Ketik path manual")
    choice = safe_input("\nPilihan (1/2): ", max_length=10, allow_empty=False).strip()
    
    file_path = ""
    if choice == "1":
        # Use tkinter file dialog
        try:
            root = tk.Tk()
            root.withdraw()  # Hide the main window
            root.attributes('-topmost', True)  # Bring dialog to front
            file_path = filedialog.askopenfilename(
                title="Pilih file untuk dienkripsi",
                filetypes=[
                    ("All Files", "*.*"),
                    ("Images", "*.jpg *.jpeg *.png *.gif *.bmp"),
                    ("Documents", "*.pdf *.doc *.docx *.txt"),
                    ("Videos", "*.mp4 *.avi *.mkv"),
                ]
            )
            root.destroy()
            
            if not file_path:
                print("\n❌ Tidak ada file yang dipilih.")
                input("\nTekan Enter untuk melanjutkan...")
                return
        except Exception as e:
            print(f"\n❌ Gagal membuka file browser: {e}")
            print("Silakan gunakan opsi ketik path manual.")
            input("\nTekan Enter untuk melanjutkan...")
            return
    elif choice == "2":
        file_path = safe_input("Masukkan path file: ", max_length=500, allow_empty=False).strip()
        if file_path.startswith('"') and file_path.endswith('"'):
            file_path = file_path[1:-1]
    else:
        print("\n❌ Pilihan tidak valid.")
        input("\nTekan Enter untuk melanjutkan...")
        return

    ok, msg = save_encrypted_file(user["user_id"], file_path, user["pub_key"], classic_key)
    print(f"\n{'✅' if ok else '❌'} {msg}")
    input("\nTekan Enter untuk melanjutkan...")

def menu_list_files(user: dict):
    print("\n=== FILE SAYA ===")
    files = list_user_files(user["user_id"])
    
    if not files:
        print("📭 Belum ada file. Upload dulu!")
    else:
        print(f"{'No':<4} {'Nama File':<30} {'Ukuran':<15} {'Tanggal'}")
        print("-" * 70)
        for i, (file_id, name, created_at, size) in enumerate(files, 1):
            size_str = f"{size:,} bytes"
            print(f"{i:<4} {name[:28]:<30} {size_str:<15} {created_at[:10]}")
    
    input("\nTekan Enter untuk melanjutkan...")
    return files

def menu_list_public_files():
    """Show all stored files with encrypted names (public view)"""
    print("\n=== FILE TERSIMPAN (PUBLIK) ===")
    print("📌 Nama file ditampilkan dalam bentuk ciphertext untuk privasi.\n")
    
    files = list_all_files_public()
    
    if not files:
        print("📭 Belum ada file tersimpan di sistem.")
    else:
        print(f"{'No':<4} {'Nama File (Ciphertext)':<32} {'Owner':<10} {'Tanggal'}")
        print("-" * 70)
        for i, (file_id, name, created_at, size, username) in enumerate(files, 1):
            encrypted_name = encrypt_display_name(name)
            masked_user = encrypt_username(username)
            print(f"{i:<4} {encrypted_name:<32} {masked_user:<10} {created_at[:10]}")
        
        print(f"\n📊 Total: {len(files)} file tersimpan")
    
    input("\nTekan Enter untuk melanjutkan...")

def menu_download(user: dict, classic_key: str):
    print("\n=== DOWNLOAD FILE ===")
    if not classic_key:
        print("❌ Classic Key belum diset! Silakan set dulu di menu 5.")
        input("\nTekan Enter untuk melanjutkan...")
        return

    files = list_user_files(user["user_id"])
    if not files:
        print("📭 Belum ada file untuk didownload.")
        input("\nTekan Enter untuk melanjutkan...")
        return

    print(f"{'No':<4} {'Nama File':<30}")
    print("-" * 35)
    for i, (file_id, name, _, _) in enumerate(files, 1):
        print(f"{i:<4} {name[:28]:<30}")

    try:
        choice_input = safe_input("\nPilih nomor file: ", max_length=10, allow_empty=False)
        choice = int(choice_input) - 1
        if 0 <= choice < len(files):
            file_id = files[choice][0]
            output_dir = safe_input("Folder output (kosong = folder saat ini): ", max_length=500, allow_empty=True).strip() or "."
            
            rec = load_file_record(file_id, user["user_id"])
            ok, msg = decrypt_file(rec, user["priv_key"], classic_key, output_dir)
            print(f"\n{'✅' if ok else '❌'} {msg}")
        else:
            print("❌ Nomor tidak valid.")
    except ValueError:
        print("❌ Input tidak valid.")
    
    input("\nTekan Enter untuk melanjutkan...")

def menu_download_public():
    """Download file from any user (requires sharing_key + classic_key)"""
    print("\n" + "═" * 55)
    print("       📥 DOWNLOAD FILE PUBLIK (Hybrid Decryption)")
    print("═" * 55)
    print("📌 Untuk download file orang lain, Anda memerlukan:")
    print("   1. Sharing Key (dari pemilik file)")
    print("   2. Classic Key (dari pemilik file)")
    print()
    
    files = list_all_files_public()
    
    if not files:
        print("📭 Belum ada file tersimpan di sistem.")
        input("\nTekan Enter untuk melanjutkan...")
        return
    
    # Display files with ciphertext names
    print(f"{'No':<4} {'Nama File (Ciphertext)':<32} {'Owner':<10} {'Ukuran'}")
    print("-" * 65)
    for i, (file_id, name, created_at, size, username) in enumerate(files, 1):
        encrypted_name = encrypt_display_name(name)
        masked_user = encrypt_username(username)
        size_str = f"{size:,} bytes"
        print(f"{i:<4} {encrypted_name:<32} {masked_user:<10} {size_str}")
    
    print(f"\n📊 Total: {len(files)} file tersedia")
    print("-" * 65)
    
    # Select file
    try:
        choice_input = safe_input("\n🔢 Pilih nomor file yang ingin didownload (0 untuk batal): ", max_length=10, allow_empty=False)
        choice = int(choice_input)
        
        if choice == 0:
            print("\n✅ Dibatalkan.")
            input("\nTekan Enter untuk melanjutkan...")
            return
            
        if choice < 1 or choice > len(files):
            print("\n❌ Nomor tidak valid.")
            input("\nTekan Enter untuk melanjutkan...")
            return
        
        selected = files[choice - 1]
        file_id, original_name, created_at, size, owner_username = selected
        encrypted_name = encrypt_display_name(original_name)
        masked_owner = encrypt_username(owner_username)
        
        # Show confirmation
        print("\n" + "-" * 50)
        print("📋 DETAIL FILE YANG DIPILIH:")
        print("-" * 50)
        print(f"   Nama (Ciphertext) : {encrypted_name}")
        print(f"   Owner             : {masked_owner}")
        print(f"   Ukuran            : {size:,} bytes")
        print(f"   Tanggal Upload    : {created_at[:10]}")
        print("-" * 50)
        
        confirm = safe_input("\n⚠️  Lanjutkan download? (y/n): ", max_length=10, allow_empty=False).lower().strip()
        if confirm != 'y':
            print("\n✅ Dibatalkan.")
            input("\nTekan Enter untuk melanjutkan...")
            return
        
        # Ask for Sharing Key (from owner)
        print("\n🔐 MASUKKAN SHARING KEY")
        print("   Sharing Key adalah kode hex yang diberikan oleh pemilik file.")
        sharing_key = safe_input("   Sharing Key: ", max_length=100, allow_empty=False).strip()
        
        # Ask for Classic Key
        print("\n🔑 MASUKKAN CLASSIC KEY")
        print("   Classic Key adalah kunci Myszkowski yang digunakan saat enkripsi.")
        classic_key = safe_input("   Classic Key: ", max_length=50, allow_empty=False).strip()
        
        if len(classic_key) < 2:
            print("\n❌ Classic Key terlalu pendek! Minimal 2 karakter.")
            input("\nTekan Enter untuk melanjutkan...")
            return
        
        # Ask for output directory
        output_dir = safe_input("\n📂 Folder output (kosong = folder saat ini): ", max_length=500, allow_empty=True).strip() or "."
        
        # Load full record and decrypt
        record = load_file_record_public(file_id)
        if not record:
            print("\n❌ File tidak ditemukan di database.")
            input("\nTekan Enter untuk melanjutkan...")
            return
        
        print("\n⏳ Mendekripsi file dengan Hybrid Decryption...")
        ok, msg = decrypt_file_public(record, sharing_key, classic_key, output_dir)
        print(f"\n{'✅' if ok else '❌'} {msg}")
        
    except ValueError:
        print("\n❌ Input tidak valid. Masukkan angka.")
    
    input("\nTekan Enter untuk melanjutkan...")

def menu_generate_sharing_key(user: dict):
    """Generate sharing key for a file owned by the user"""
    print("\n" + "═" * 55)
    print("       🔗 GENERATE SHARING KEY")
    print("═" * 55)
    print("📌 Sharing Key memungkinkan orang lain mendownload file Anda.")
    print("📌 Berikan Sharing Key + Classic Key kepada penerima.\n")
    
    files = list_user_files(user["user_id"])
    
    if not files:
        print("📭 Belum ada file. Upload dulu!")
        input("\nTekan Enter untuk melanjutkan...")
        return
    
    # Display files
    print(f"{'No':<4} {'Nama File':<30} {'Tanggal'}")
    print("-" * 50)
    for i, (file_id, name, created_at, size) in enumerate(files, 1):
        print(f"{i:<4} {name[:28]:<30} {created_at[:10]}")
    
    try:
        choice_input = safe_input("\n🔢 Pilih nomor file: ", max_length=10, allow_empty=False)
        choice = int(choice_input) - 1
        
        if choice < 0 or choice >= len(files):
            print("\n❌ Nomor tidak valid.")
            input("\nTekan Enter untuk melanjutkan...")
            return
        
        file_id = files[choice][0]
        file_name = files[choice][1]
        
        # Load file record to get wrapped_seed
        rec = load_file_record(file_id, user["user_id"])
        if not rec:
            print("\n❌ File tidak ditemukan.")
            input("\nTekan Enter untuk melanjutkan...")
            return
        
        _, original_name, stored_name, wrapped_seed = rec
        
        # Decrypt wrapped_seed using user's RSA private key
        try:
            random_seed = rsa_decrypt(user["priv_key"], wrapped_seed)
            sharing_key = random_seed.hex()
        except Exception as e:
            print(f"\n❌ Gagal generate sharing key: {e}")
            input("\nTekan Enter untuk melanjutkan...")
            return
        
        # Display sharing key
        print("\n" + "═" * 55)
        print("✅ SHARING KEY BERHASIL DIBUAT!")
        print("═" * 55)
        print(f"\n📄 File: {file_name}")
        print("\n🔗 SHARING KEY (berikan ke penerima):")
        print("-" * 55)
        print(f"{sharing_key}")
        print("-" * 55)
        print("\n⚠️  PENTING:")
        print("   • Sharing Key ini hanya untuk file ini saja")
        print("   • Jangan lupa berikan juga Classic Key kepada penerima")
        print("   • Simpan key ini dengan aman, tidak bisa di-recover jika hilang")
        
    except ValueError:
        print("\n❌ Input tidak valid.")
    
    input("\nTekan Enter untuk melanjutkan...")

def menu_delete(user: dict):
    print("\n=== HAPUS FILE ===")
    files = list_user_files(user["user_id"])
    if not files:
        print("📭 Belum ada file untuk dihapus.")
        input("\nTekan Enter untuk melanjutkan...")
        return

    print(f"{'No':<4} {'Nama File':<30}")
    print("-" * 35)
    for i, (file_id, name, _, _) in enumerate(files, 1):
        print(f"{i:<4} {name[:28]:<30}")

    try:
        choice_input = safe_input("\nPilih nomor file yang akan dihapus: ", max_length=10, allow_empty=False)
        choice = int(choice_input) - 1
        if 0 <= choice < len(files):
            file_id = files[choice][0]
            confirm = safe_input(f"Yakin hapus '{files[choice][1]}'? (y/n): ", max_length=10, allow_empty=False).lower()
            if confirm == 'y':
                ok, msg = delete_file(file_id, user["user_id"])
                print(f"\n{'✅' if ok else '❌'} {msg}")
            else:
                print("Dibatalkan.")
        else:
            print("❌ Nomor tidak valid.")
    except ValueError:
        print("❌ Input tidak valid.")
    
    input("\nTekan Enter untuk melanjutkan...")

def menu_ganti_key():
    print("\n=== GANTI CLASSIC KEY ===")
    print("Classic Key adalah kunci untuk enkripsi Myszkowski.")
    print("Key: 4-50 karakter alfanumerik.")
    new_key = safe_input("Masukkan Classic Key baru: ", max_length=50, allow_empty=False).strip()
    
    if len(new_key) < 4:
        print("❌ Key terlalu pendek! Minimal 4 karakter.")
        input("\nTekan Enter untuk melanjutkan...")
        return None
    
    if not any(c.isalnum() for c in new_key):
        print("❌ Key harus mengandung karakter alfanumerik!")
        input("\nTekan Enter untuk melanjutkan...")
        return None
    
    print(f"✅ Classic Key berhasil diubah!")
    input("\nTekan Enter untuk melanjutkan...")
    return new_key

def main():
    init_db()
    current_user = None
    classic_key = ""

    while True:
        clear_screen()
        print_header()

        if current_user is None:
            # Menu utama (belum login)
            print_menu_utama()
            choice = safe_input("\nPilih menu: ", max_length=10).strip()

            if choice == "1":
                menu_register()
            elif choice == "2":
                current_user = menu_login()
            elif choice == "3":
                menu_list_public_files()
            elif choice == "4":
                print("\n👋 Terima kasih telah menggunakan SecureVault!")
                break
            else:
                print("❌ Pilihan tidak valid.")
                input("\nTekan Enter untuk melanjutkan...")
        else:
            # Menu user (sudah login)
            print_menu_user(current_user["username"], classic_key)
            choice = safe_input("\nPilih menu: ", max_length=10).strip()

            if choice == "1":
                menu_upload(current_user, classic_key)
            elif choice == "2":
                menu_list_files(current_user)
            elif choice == "3":
                menu_download(current_user, classic_key)
            elif choice == "4":
                menu_download_public()
            elif choice == "5":
                menu_generate_sharing_key(current_user)
            elif choice == "6":
                menu_delete(current_user)
            elif choice == "7":
                new_key = menu_ganti_key()
                if new_key:
                    classic_key = new_key
            elif choice == "8":
                current_user = None
                classic_key = ""
                print("\n✅ Logout berhasil!")
                input("\nTekan Enter untuk melanjutkan...")
            else:
                print("❌ Pilihan tidak valid.")
                input("\nTekan Enter untuk melanjutkan...")

if __name__ == "__main__":
    main()
