# Passwordless Cloud Authentication Using Biometric-Derived Keys and Elliptic Curve Signature

## Project Overview

This project develops a passwordless cloud authentication system using
biometric-derived cryptographic keys and Elliptic Curve Cryptography
(ECC). Instead of relying on traditional passwords, the system uses a
biometric sample to derive a cryptographic key. The Elliptic Curve
Digital Signature Algorithm (ECDSA) is then used to authenticate the
user.

The goal is to improve authentication security, reduce password-related
risks, and protect biometric privacy.

## Objectives

-   Replace traditional password-based login with biometric
    authentication.
-   Process biometric input locally to protect user privacy.
-   Use SHA-256 hashing to generate a fixed-length digest.
-   Generate ECC public and private key pairs.
-   Use ECDSA digital signatures to verify authentication requests.
-   Reduce the risk of phishing, replay attacks, and credential theft.

## Existing System

Traditional cloud authentication commonly depends on passwords.
Passwords can be weak, reused, stolen, or exposed through phishing and
data breaches. Biometric-only systems may also create privacy risks if
raw biometric data or templates are stored centrally.

## Proposed System

The proposed system combines biometric input with ECC-based
cryptographic authentication.

### Registration Workflow

1.  The user provides a fingerprint through the biometric scanner.
2.  The client processes the biometric input and derives a hash using
    SHA-256.
3.  The derived value is used in the ECC key-generation process.
4.  The public key and user identity are registered with the server.
5.  The private key is intended to remain on the client side.

### Authentication Workflow

1.  The user starts the login process.
2.  The server provides an authentication challenge.
3.  The user scans their fingerprint again.
4.  The client reconstructs the required key material.
5.  The client signs the challenge using ECDSA.
6.  The server verifies the signature using the registered public key.
7.  Access is granted when verification succeeds; otherwise, access is
    denied.

## Technologies Used

-   **Programming Language:** Python
-   **Backend Framework:** Flask
-   **Frontend:** HTML and CSS
-   **Cryptography:** Elliptic Curve Cryptography (ECC), ECDSA
-   **Hashing:** SHA-256
-   **Biometric Hardware:** Mantra RD MFS110 fingerprint scanner
-   **Operating System:** Windows 10/11
-   **Development Tools:** Visual Studio Code / PyCharm

## Hardware Requirements

-   Intel i5 processor or equivalent
-   Minimum 8 GB RAM for server and 4 GB RAM for client
-   256 GB SSD or higher
-   Mantra RD MFS110 fingerprint scanner
-   Stable network connection

## Software Requirements

-   Windows 10 or Windows 11
-   Python
-   Flask
-   Required Python cryptography and ECDSA libraries
-   HTML and CSS support
-   Fingerprint scanner drivers and RD service

## Main Modules

1.  **Biometric Capture:** Captures the user's fingerprint using the
    scanner.
2.  **Feature and Hash Processing:** Processes biometric input and
    creates a SHA-256 digest.
3.  **ECC Key Generation:** Creates the corresponding cryptographic key
    pair.
4.  **User Registration:** Registers the user's identity and public key.
5.  **ECDSA Signing:** Signs the authentication challenge on the client
    side.
6.  **Signature Verification:** Verifies the signature using the
    registered public key.
7.  **Access Control:** Grants or denies access based on verification.

## Security Features

-   Passwordless authentication
-   Local biometric processing as described in the project design
-   Public-key-based signature verification
-   Challenge-response authentication
-   Protection designed to reduce phishing and replay risks
-   Avoidance of storing raw biometric samples on the cloud server

## Project Team

-   **Penki Jyothi** --- 5221411202
-   **Kosuru Kamakshi** --- 5221411192
-   **Yarra Vasu** --- 5221411169
-   **Y. V. Avinash** --- 5221411210

**Project Guide:** Dr. Bh. Padma, Professor\
**Department:** Computer Science and Engineering\
**Institution:** Gayatri Vidya Parishad College for Degree and PG
Courses (A), Visakhapatnam\
**Academic Year:** 2022--2026

## Note

The exact installation commands and execution steps depend on the Python
files and dependency versions in the project repository. Add the
verified commands from your project setup before publishing this README.

## Conclusion

The project demonstrates a passwordless authentication approach that
combines biometric input, SHA-256 hashing, ECC key generation, and ECDSA
digital signatures. It aims to provide secure and privacy-conscious
cloud authentication without relying on traditional passwords.
