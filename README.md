# Information Security

[![License](https://img.shields.io/github/license/eludwig17/Information-Security)](https://github.com/eludwig17/Information-Security/blob/main/LICENSE) [![Top Language](https://img.shields.io/github/languages/top/eludwig17/Information-Security)](https://github.com/eludwig17/Information-Security) [![Open Issues](https://img.shields.io/github/issues/eludwig17/Information-Security)](https://github.com/eludwig17/Information-Security/issues) [![Last Commit](https://img.shields.io/github/last-commit/eludwig17/Information-Security)](https://github.com/eludwig17/Information-Security/commits/main)

This repository is intended for education, experimentation, and reference; not for production usage. These are files programmed by me for my information Security Course at Concordia University Irvine which I learned the fundamentals of information & cyber security that covered the topics of historical, modern cryptography, and computer system security.

---

Table of contents

- About
- Code

---

About
This repository contains several Python implementations and demonstrations of encryption-related algorithms (DES family, RSA, and GNU Privacy Guard related utilities). Each script is documented in-code and demonstrates algorithm internals and test vectors for learning.


Code files 

DES (classic DES / 3DES implementations and tests)
- [DES/TDES.py](https://github.com/eludwig17/Information-Security/blob/main/DES/TDES.py) — Triple DES (3DES) implementation.
- [DES/cuiDES.py](https://github.com/eludwig17/Information-Security/blob/main/DES/cuiDES.py) — Original DES implementation
- [DES/des_constants_permutation_tables.py](https://github.com/eludwig17/Information-Security/blob/main/DES/des_constants_permutation_tables.py) — DES permutation tables used by the algorithm.
- [DES/des_constants_sbox_tables.py](https://github.com/eludwig17/Information-Security/blob/main/DES/des_constants_sbox_tables.py) — DES S-box definitions.
- [DES/des_constants_subkey_tables.py](https://github.com/eludwig17/Information-Security/blob/main/DES/des_constants_subkey_tables.py) — Key schedule constants for subkey generation.
- [DES/des_tests_subkey.py](https://github.com/eludwig17/Information-Security/blob/main/DES/des_tests_subkey.py) — Test vectors and unit-like checks for the DES subkey scheduling.
- [DES/elud_SBOXtest.py](https://github.com/eludwig17/Information-Security/blob/main/DES/elud_SBOXtest.py) — Small S-box test harness.
- [DES/elud_des_permTables.py](https://github.com/eludwig17/Information-Security/blob/main/DES/elud_des_permTables.py) — Permutation table.
- [DES/homework09.py](https://github.com/eludwig17/Information-Security/blob/main/DES/homework09.py)
- [DES/homework10.py](https://github.com/eludwig17/Information-Security/blob/main/DES/homework10.py)

RSA (asymmetric crypto demonstrations)
- [RSA/rsa.py](https://github.com/eludwig17/Information-Security/blob/main/RSA/rsa.py) — RSA key generation, encryption/decryption, signing and verification functions with examples and comments.

GNU Privacy Guard Project (GPG-related scripts / 3DES & helpers)
- [GNU Privacy Guard Project/TDES.py](https://github.com/eludwig17/Information-Security/blob/main/GNU%20Privacy%20Guard%20Project/TDES.py) — Another 3DES-focused implementation/use-case inspired by GPG internals.
- [GNU Privacy Guard Project/des_constants_permutation_tables.py](https://github.com/eludwig17/Information-Security/blob/main/GNU%20Privacy%20Guard%20Project/des_constants_permutation_tables.py) — Permutation tables (copy/variant used for GPG-focused scripts).
- [GNU Privacy Guard Project/des_constants_sbox_tables.py](https://github.com/eludwig17/Information-Security/blob/main/GNU%20Privacy%20Guard%20Project/des_constants_sbox_tables.py) — S-box tables.
- [GNU Privacy Guard Project/des_constants_subkey_tables.py](https://github.com/eludwig17/Information-Security/blob/main/GNU%20Privacy%20Guard%20Project/des_constants_subkey_tables.py) — Subkey schedule constants (GPG folder variant).
- [GNU Privacy Guard Project/gpg_consts.py](https://github.com/eludwig17/Information-Security/blob/main/GNU%20Privacy%20Guard%20Project/gpg_consts.py) — GPG-related constants and helper definitions.
- [GNU Privacy Guard Project/gpg_decrypt.py](https://github.com/eludwig17/Information-Security/blob/main/GNU%20Privacy%20Guard%20Project/gpg_decrypt.py) — Example script exploring GPG-style decryption flows.

License
This project is licensed under the MIT License. See [LICENSE](https://github.com/eludwig17/Information-Security/blob/main/LICENSE) for details.

Thank you for exploring my Information Security Repository.
