**Encrypted File System (EFS) Implementation**

*   Designed and implemented a secure file system in Java using **AES-128 encryption (CTR mode)** and **SHA-256 hashing** to protect file confidentiality and integrity.
    
*   Engineered user authentication with **salted password hashing (PBKDF2)** to mitigate brute-force and dictionary attacks.
    
*   Developed file operations (create, read, write) with **HMAC-SHA256 integrity checks**, ensuring detection of unauthorized tampering.
    
*   Optimized storage efficiency by splitting files into **1024-byte encrypted blocks** and minimizing disk access during read/write operations.
    
*   Secured metadata and file content using unique IVs per block to prevent cryptographic pattern leakage.
    
*   **Technologies:** Java, AES-128, SHA-256, HMAC, Git, OOP, File I/O, Cryptography.
