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

