# Threshold ElGamal with Shamir Secret Sharing (t = 2, n = 5)

## Author
Rownak Jahan Chowdhury

Applied Cryptography Project

---

## Overview
This project demonstrates **Threshold ElGamal decryption** using **Shamir Secret Sharing**.  
The private key is split among multiple players, and **at least t+1 players** are required to decrypt.  
The secret key is **never reconstructed** in one place.

---

## What This Program Does (Simple Story)
- **Alice** wants to send a secret message securely.
- A group of **5 players** holds pieces of the secret key.
- Any **3 players** (because t = 2 → need t+1 = 3) can work together to decrypt.
- No single player can decrypt alone.

---

## Steps Implemented

### 1) Load Public Parameters
Loads the group parameters used for ElGamal:
- prime modulus **p**
- subgroup prime **q**
- generator **g**

### 2) Key Generation
- Generate secret key `a` in **Zq**
- Compute public key `A = g^a mod p`

### 3) Shamir Secret Sharing (t = 2, n = 5)
- Create a random polynomial `f(x)` of degree `t`
- Set `f(0) = a` (the secret)
- Give each player one share: `a_i = f(i)`

### 4) Threshold (Distributed) Decryption
To decrypt, each selected player computes a **partial decryption**:
- `D_i = B^(a_i) mod p`

Then we combine partial decryptions using **Lagrange weights** so that:
- The final result matches using the real key `a`
- But `a` is never reconstructed

### 5) Hybrid Encryption (ElGamal + AES)
- ElGamal produces a shared secret `S`
- `SHA-256(S)` gives a **32-byte AES key**
- Message is encrypted using **AES-256-GCM**
- After threshold decryption, the message is recovered

---

## How to Build and Run

### Build
```bash
make
./threshold_elgamal
```

## Expected Output (High Level)
- Confirms parameters loaded  
- Confirms threshold setup (t = 2, n = 5)  
- Confirms partial decryptions computed  
- Confirms threshold result matches direct result  
- Prints the recovered plaintext message  

---

## File Structure
- `main.cpp` : runs all parts (setup → sharing → threshold decrypt → AES test)  
- `params.cpp/.h` : loads `p`, `q`, `g` parameters  
- `shamir.cpp/.h` : split and reconstruct secret using Shamir sharing  
- `lagrange.cpp/.h` : computes Lagrange weights at `x = 0`  
- `threshold.cpp/.h` : partial decrypt + combine partials  
- `crypto.cpp/.h` : SHA-256 key derivation + AES-256-GCM encrypt/decrypt  
- `Makefile` : build instructions  

---

## Notes
- This is a learning/demo implementation for coursework.  
- Real-world secure systems require careful key handling, validation, and constant-time operations.

---

## Project Specification

**Project Specification (Provided by Instructor):**  
Project_Description.docx
