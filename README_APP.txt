================================================================================
                        DOKUMENTASI APLIKASI SECUREVAULT
                     Aplikasi Penyimpanan File Terenkripsi
                      Hybrid Cryptography: Myszkowski + RSA
================================================================================

DESKRIPSI SINGKAT
-----------------
SecureVault adalah aplikasi CLI untuk penyimpanan file secara aman dengan 
menggunakan **Hybrid Encryption** yang menggabungkan dua algoritma:
  • Myszkowski Transposition Cipher (algoritma klasik)
  • RSA 2048-bit (algoritma modern)

Kedua algoritma WAJIB digunakan bersama - file tidak bisa didekripsi tanpa
memiliki KEDUA kunci (Classic Key + RSA/Sharing Key).

================================================================================
                         MATERI PRESENTASI 5 MENIT
================================================================================

┌─────────────────────────────────────────────────────────────────────────────┐
│  SLIDE 1: PENDAHULUAN (30 detik)                                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  SecureVault - Aplikasi penyimpanan file dengan keamanan ganda:             │
│                                                                             │
│  ┌───────────────┐    ┌───────────────┐                                     │
│  │  MYSZKOWSKI   │ +  │     RSA       │  = HYBRID ENCRYPTION                │
│  │   (Klasik)    │    │   (Modern)    │                                     │
│  └───────────────┘    └───────────────┘                                     │
│                                                                             │
│  Keunggulan: File hanya bisa dibuka jika memiliki KEDUA kunci               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  SLIDE 2: ALGORITMA MYSZKOWSKI (1 menit)                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  MYSZKOWSKI TRANSPOSITION CIPHER                                            │
│  ─────────────────────────────────                                          │
│  • Cipher transposisi klasik (permutasi posisi karakter)                    │
│  • Menggunakan keyword sebagai kunci (Classic Key)                          │
│                                                                             │
│  Contoh dengan key "TOMATO":                                                │
│                                                                             │
│   T  O  M  A  T  O    ← Key                                                 │
│   4  2  1  0  4  2    ← Rank (A=0, M=1, O=2, T=4)                           │
│  ─────────────────                                                          │
│   H  E  L  L  O  ·    ← Plaintext "HELLO" diisi ke grid                     │
│   W  O  R  L  D  ·                                                          │
│                                                                             │
│  Baca kolom berdasarkan rank: A→M→O,O→T,T = "LL" + "LR" + "EO OD" + "HW"    │
│  Ciphertext: "LLLREOⅮHW" (karakter teracak berdasarkan key)                 │
│                                                                             │
│  ✓ Kelebihan: Sederhana, cepat untuk data besar                             │
│  ✗ Kekurangan: Rentan jika key diketahui                                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  SLIDE 3: ALGORITMA RSA (1 menit)                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  RSA (Rivest-Shamir-Adleman)                                                │
│  ───────────────────────────                                                │
│  • Algoritma kriptografi asimetris (public/private key)                     │
│  • Keamanan berbasis kesulitan faktorisasi bilangan prima besar             │
│                                                                             │
│  Cara Kerja:                                                                │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐                 │
│  │  PLAINTEXT   │ ──► │  PUBLIC KEY  │ ──► │  CIPHERTEXT  │                 │
│  │   (Data)     │     │  (Enkripsi)  │     │  (Terkunci)  │                 │
│  └──────────────┘     └──────────────┘     └──────────────┘                 │
│         ▲                                         │                         │
│         │            ┌──────────────┐             │                         │
│         └────────────│ PRIVATE KEY  │◄────────────┘                         │
│                      │  (Dekripsi)  │                                       │
│                      └──────────────┘                                       │
│                                                                             │
│  ✓ Kelebihan: Sangat aman, key exchange tanpa shared secret                 │
│  ✗ Kekurangan: Lambat untuk data besar                                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  SLIDE 4: HYBRID ENCRYPTION - CARA KERJA (1.5 menit)                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PROSES ENKRIPSI (UPLOAD FILE):                                             │
│  ══════════════════════════════                                             │
│                                                                             │
│   ┌──────────┐                                                              │
│   │   FILE   │                                                              │
│   │  (Asli)  │                                                              │
│   └────┬─────┘                                                              │
│        │                                                                    │
│        ▼  Layer 1: Myszkowski                                               │
│   ┌─────────────────────────────┐                                           │
│   │  myszkowski_encrypt(file,  │◄──── Classic Key (user input)              │
│   │       classic_key)         │      Contoh: "SECRET123"                   │
│   └────────────┬────────────────┘                                           │
│                │                                                            │
│                ▼  Layer 2: XOR dengan Random Seed                           │
│   ┌─────────────────────────────┐                                           │
│   │   XOR(mys_encrypted,       │◄──── Random Seed (32 bytes)                │
│   │       random_seed)         │      Auto-generated                        │
│   └────────────┬────────────────┘                                           │
│                │                                                            │
│                ▼                                                            │
│   ┌─────────────────────────────┐     ┌─────────────────────────────┐       │
│   │   FILE TERENKRIPSI         │     │   RSA_encrypt(random_seed,  │       │
│   │   (Disimpan di storage/)   │     │      user_public_key)       │       │
│   └─────────────────────────────┘     └──────────────┬──────────────┘       │
│                                                      │                      │
│                                                      ▼                      │
│                                       ┌─────────────────────────────┐       │
│                                       │   WRAPPED SEED              │       │
│                                       │   (Disimpan di database)    │       │
│                                       └─────────────────────────────┘       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  SLIDE 5: PROSES DEKRIPSI & SHARING (1 menit)                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  DEKRIPSI OLEH OWNER:                                                       │
│  ────────────────────                                                       │
│  1. RSA_decrypt(wrapped_seed, private_key) → random_seed                    │
│  2. XOR(encrypted_file, random_seed) → mys_encrypted                        │
│  3. myszkowski_decrypt(mys_encrypted, classic_key) → FILE ASLI              │
│                                                                             │
│  BUTUH: RSA Private Key ✓ + Classic Key ✓                                   │
│                                                                             │
│  ═══════════════════════════════════════════════════════════════════════    │
│                                                                             │
│  SHARING FILE KE ORANG LAIN:                                                │
│  ──────────────────────────                                                 │
│                                                                             │
│   OWNER                              RECIPIENT                              │
│   ┌───────────────────┐             ┌───────────────────┐                   │
│   │ Generate Sharing  │   Share     │ Download File     │                   │
│   │ Key (menu 5)      │ ─────────►  │ Publik (menu 4)   │                   │
│   │                   │             │                   │                   │
│   │ Sharing Key: abc..│ + Classic   │ Input:            │                   │
│   │ Classic Key: XYZ  │   Key       │ • Sharing Key     │                   │
│   └───────────────────┘             │ • Classic Key     │                   │
│                                     └───────────────────┘                   │
│                                                                             │
│  Sharing Key = random_seed dalam format hex (owner decrypt dengan RSA)      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  SLIDE 6: KEAMANAN & KESIMPULAN (30 detik)                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ANALISIS KEAMANAN:                                                         │
│  ┌──────────────────────────────────┬─────────────────┐                     │
│  │ Skenario                         │ Bisa Decrypt?   │                     │
│  ├──────────────────────────────────┼─────────────────┤                     │
│  │ Punya RSA Private Key saja       │      ❌ TIDAK   │                     │
│  │ Punya Classic Key saja           │      ❌ TIDAK   │                     │
│  │ Punya Sharing Key saja           │      ❌ TIDAK   │                     │
│  │ RSA + Classic Key (owner)        │      ✅ YA      │                     │
│  │ Sharing Key + Classic Key        │      ✅ YA      │                     │
│  └──────────────────────────────────┴─────────────────┘                     │
│                                                                             │
│  KESIMPULAN:                                                                │
│  • Hybrid encryption menggabungkan kelebihan kedua algoritma                │
│  • Myszkowski: cepat untuk enkripsi file besar                              │
│  • RSA: aman untuk melindungi kunci enkripsi                                │
│  • Sistem sharing yang fleksibel tanpa membagikan private key               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

================================================================================
                            REFERENSI TEKNIS
================================================================================

STRUKTUR DATABASE (SQLite)
--------------------------
Tabel 'users':
  - id, username, password_hash
  - rsa_public_pem, rsa_private_pem_enc (terenkripsi password)
  - created_at

Tabel 'files':
  - id, user_id, original_name, stored_name
  - wrapped_key (RSA-encrypted random_seed)
  - mys_key_length, created_at, size_bytes

STRUKTUR FOLDER
---------------
project/
├── app.py           → Aplikasi utama
├── data/
│   └── app.db       → Database SQLite
└── storage/
    └── *.enc        → File terenkripsi

TEKNOLOGI
---------
- Python 3.x
- Library: cryptography (RSA), sqlite3
- RSA: 2048-bit dengan OAEP padding + SHA-256
- Password: SHA-256 dengan salt (16 bytes)

================================================================================
                          © SecureVault - File Storage
                       Hybrid Cryptography: Myszkowski + RSA
================================================================================
