# 🔐 SecureVault - File Storage with Hybrid Encryption

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white)
![Cryptography](https://img.shields.io/badge/Cryptography-RSA%20%2B%20Myszkowski-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-Academic-orange?style=for-the-badge)

**Aplikasi Penyimpanan File dengan Enkripsi Hybrid**  
_Menggabungkan Algoritma Klasik (Myszkowski) dan Modern (RSA)_

---

### 👨‍💻 Credits

|               Nama               |      NIM       |   Kelas   |
| :------------------------------: | :------------: | :-------: |
| **Farros Rifantiarno Ramadhani** | A11.2024.15694 | A11.43UG1 |

**Tugas Akhir Mata Kuliah Kriptografi**

---

</div>

## 📋 Daftar Isi

- [Tentang Aplikasi](#-tentang-aplikasi)
- [Fitur Utama](#-fitur-utama)
- [Algoritma yang Digunakan](#-algoritma-yang-digunakan)
- [Cara Kerja Enkripsi](#-cara-kerja-enkripsi)
- [Instalasi](#-instalasi)
- [Panduan Penggunaan](#-panduan-penggunaan)
- [Keamanan](#-keamanan)
- [Struktur Project](#-struktur-project)

---

## 🎯 Tentang Aplikasi

**SecureVault** adalah aplikasi CLI (Command Line Interface) untuk menyimpan file secara aman menggunakan **Hybrid Encryption** yang menggabungkan:

| Algoritma                    | Tipe   | Fungsi                          |
| ---------------------------- | ------ | ------------------------------- |
| **Myszkowski Transposition** | Klasik | Enkripsi file (Layer 1)         |
| **RSA 2048-bit**             | Modern | Proteksi kunci (Layer 2)        |
| **SHA-256**                  | Hash   | Password hashing & OAEP padding |

> ⚠️ **Keamanan Ganda**: File hanya bisa didekripsi jika memiliki **KEDUA kunci** (Classic Key + RSA/Sharing Key)

---

## ✨ Fitur Utama

```
✅ Registrasi dengan auto-generate RSA Key Pair (2048-bit)
✅ Login dengan password terenkripsi (SHA-256 + Salt)
✅ Upload file dengan enkripsi hybrid
✅ Download file pribadi (dengan RSA + Classic Key)
✅ Share file ke user lain (Generate Sharing Key)
✅ Download file publik (dengan Sharing Key + Classic Key)
✅ Lihat daftar file (nama ditampilkan sebagai ciphertext)
✅ Hapus file
```

---

## 🔬 Algoritma yang Digunakan

### 1️⃣ Myszkowski Transposition Cipher

Cipher transposisi klasik yang menggunakan keyword untuk mengacak posisi karakter.

```
Keyword: TOMATO → Ranks: [3, 2, 1, 0, 3, 2]

Grid:    T  O  M  A  T  O
         3  2  1  0  3  2
        ─────────────────
         H  E  L  L  O  ·
         W  O  R  L  D  ·

Baca berdasarkan rank (0→1→2→3):
Output: LL + LR + EOOD + HW = "LLLREOODHW"
```

### 2️⃣ RSA (Rivest-Shamir-Adleman)

Algoritma asimetris modern dengan pasangan kunci:

| Key             | Fungsi   | Akses                   |
| --------------- | -------- | ----------------------- |
| **Public Key**  | Enkripsi | Publik (siapa saja)     |
| **Private Key** | Dekripsi | Rahasia (hanya pemilik) |

```
Spesifikasi:
├── Key Size: 2048-bit
├── Public Exponent (e): 65537
├── Padding: OAEP + SHA-256
└── p, q: Auto-generated prime numbers
```

### 3️⃣ SHA-256

Hash function untuk keamanan password dan RSA padding:

- Output: 256-bit (64 karakter hex)
- Bersifat one-way (tidak bisa di-reverse)

---

## 🔄 Cara Kerja Enkripsi

### Proses Upload (Enkripsi)

```
                    ┌─────────────┐
                    │  FILE ASLI  │
                    └──────┬──────┘
                           │
           ┌───────────────▼───────────────┐
           │  Layer 1: MYSZKOWSKI          │
           │  myszkowski_encrypt(file,     │◄── Classic Key
           │       classic_key)            │    (user input)
           └───────────────┬───────────────┘
                           │
           ┌───────────────▼───────────────┐
           │  Layer 2: XOR                 │
           │  xor(mys_encrypted,           │◄── Random Seed
           │      random_seed)             │    (32 bytes)
           └───────────────┬───────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
    ┌─────────────────┐      ┌─────────────────────┐
    │ FILE.enc        │      │ RSA_encrypt(seed,   │
    │ (tersimpan)     │      │   public_key)       │
    └─────────────────┘      └──────────┬──────────┘
                                        ▼
                              ┌─────────────────┐
                              │  wrapped_seed   │
                              │  (di database)  │
                              └─────────────────┘
```

### Proses Download (Dekripsi)

```
Owner:   wrapped_seed → RSA_decrypt(private_key) → seed
                ↓
         XOR(encrypted_file, seed) → mys_encrypted
                ↓
         myszkowski_decrypt(mys_encrypted, classic_key)
                ↓
            FILE ASLI

Recipient: Perlu Sharing Key + Classic Key dari owner
```

---

## 🚀 Instalasi

### Prasyarat

- Python 3.8 atau lebih baru
- pip (Python package manager)

### Langkah Instalasi

```bash
# 1. Clone repository
git clone https://github.com/Elnathz/filestorageRSA_Myzowski.git
cd filestorageRSA_Myzowski

# 2. Buat virtual environment (opsional tapi direkomendasikan)
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/Mac
source .venv/bin/activate

# 3. Install dependencies
pip install cryptography

# 4. Jalankan aplikasi
python app.py
```

---

## 📖 Panduan Penggunaan

### 🔹 Menu Utama (Belum Login)

```
╔══════════════════════════════════════════╗
║              MENU UTAMA                  ║
╠══════════════════════════════════════════╣
║  1. Register                             ║
║  2. Login                                ║
║  3. Lihat File Tersimpan (Publik)        ║
║  4. Keluar                               ║
╚══════════════════════════════════════════╝
```

### 🔹 Menu User (Sudah Login)

```
╔══════════════════════════════════════════╗
║  1. Upload File                          ║
║  2. Lihat File Saya                      ║
║  3. Download File Saya                   ║
║  4. Download File Publik                 ║
║  5. Generate Sharing Key                 ║
║  6. Hapus File                           ║
║  7. Ganti Classic Key                    ║
║  8. Logout                               ║
╚══════════════════════════════════════════╝
```

### 📤 Cara Upload File

1. Login ke akun Anda
2. Pilih menu **7. Ganti Classic Key** → masukkan key (minimal 4 karakter)
3. Pilih menu **1. Upload File**
4. Pilih file melalui dialog atau ketik path manual
5. File akan dienkripsi dan disimpan!

### 📥 Cara Download File Sendiri

1. Pilih menu **3. Download File Saya**
2. Pilih nomor file
3. Masukkan **Classic Key** yang digunakan saat upload
4. File akan didekripsi dan disimpan!

### 🔗 Cara Share File ke Orang Lain

**Owner (yang punya file):**

1. Pilih menu **5. Generate Sharing Key**
2. Pilih file yang ingin di-share
3. Catat **Sharing Key** (hex string panjang)
4. Berikan **Sharing Key + Classic Key** ke recipient

**Recipient (yang menerima):**

1. Pilih menu **4. Download File Publik**
2. Pilih file berdasarkan ciphertext name
3. Masukkan **Sharing Key** dari owner
4. Masukkan **Classic Key** dari owner
5. File akan didekripsi!

---

## 🛡️ Keamanan

### Analisis Keamanan

| Skenario Serangan          | Apakah Aman? | Alasan                           |
| -------------------------- | :----------: | -------------------------------- |
| Punya RSA Private Key saja |      ✅      | Butuh Classic Key juga           |
| Punya Classic Key saja     |      ✅      | Butuh RSA/Sharing Key            |
| Punya Sharing Key saja     |      ✅      | Butuh Classic Key juga           |
| Database bocor             |      ✅      | Private key terenkripsi password |
| Brute force password       |      ✅      | SHA-256 + Salt                   |

### Prinsip Keamanan

```
🔒 Defense in Depth     - Dua layer enkripsi
🔒 Least Privilege      - Sharing Key hanya untuk 1 file
🔒 Key Separation       - RSA key terpisah dari Classic Key
🔒 No Plaintext Storage - Password & private key terenkripsi
```

---

## 📁 Struktur Project

```
filestorageRSA_Myzowski/
│
├── app.py              # Aplikasi utama
├── README.md           # Dokumentasi
├── requirements.txt    # Dependencies
│
├── data/
│   └── app.db          # Database SQLite (auto-generated)
│
└── storage/
    └── *.enc           # File terenkripsi (auto-generated)
```

### Database Schema

```sql
-- Tabel Users
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,          -- SHA-256 + Salt
    rsa_public_pem TEXT,         -- Public key (plain)
    rsa_private_pem_enc BLOB,    -- Private key (encrypted)
    created_at TEXT
);

-- Tabel Files
CREATE TABLE files (
    id TEXT PRIMARY KEY,
    user_id INTEGER,
    original_name TEXT,
    stored_name TEXT,
    wrapped_key BLOB,            -- RSA-encrypted seed
    mys_key_length INTEGER,
    created_at TEXT,
    size_bytes INTEGER
);
```

---

## 📚 Referensi

- [Myszkowski Transposition Cipher](https://en.wikipedia.org/wiki/Transposition_cipher)
- [RSA Cryptosystem](<https://en.wikipedia.org/wiki/RSA_(cryptosystem)>)
- [SHA-256](https://en.wikipedia.org/wiki/SHA-2)
- [Python Cryptography Library](https://cryptography.io/)

---

<div align="center">

**Made with ❤️ for Cryptography Course**

_Universitas Dian Nuswantoro - 2024_

</div>
