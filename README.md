# CurveBall (CVE-2020-0601) Demonstration Project

This project demonstrates the **CurveBall vulnerability (CVE-2020-0601)** - a critical flaw in Windows CryptoAPI's ECC certificate validation allowing attackers to spoof certificates by manipulating elliptic curve parameters.

---

## Table of Contents

* [Overview](#overview)
* [Mathematical Background](#mathematical-background)
* [Project Structure](#project-structure)
* [Setup and Usage](#setup-and-usage)

  * [Generating a Server Certificate](#generating-a-server-certificate)
  * [Running the Server](#running-the-server)
  * [Running the Client](#running-the-client)
  * [Generating and Running the Attacker Server](#generating-and-running-the-attacker-server)
* [How the Attack Works](#how-the-attack-works)
* [Notes](#notes)

---

## Overview

CurveBall exploits a failure in curve parameter validation during ECC certificate verification, allowing attackers to spoof legitimate certificates by setting:

* d' = 1
* G' = Q

Where Q = Q' = d'G'.

This project simulates the attack by implementing:

* A **server** that serves a legitimate certificate.
* A **client** that verifies the certificate, with a vulnerable mode ignoring curve base validation.
* An **attacker server** that serves a malicious certificate crafted to exploit the vulnerability.
* Tools to **generate** legitimate and malicious certificates.

---

## Mathematical Background

For detailed mathematical details of the vulnerability, please refer to [Microsoft's security advisory](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0601) or cryptographic research papers.

Briefly, the attacker crafts a malicious certificate by manipulating the elliptic curve parameters to trick the client into accepting a fake certificate as valid.

---

## Project Structure

```
cryptographic_failure/
ÃÄÄ attacker/
³   ÃÄÄ __init__.py
³   ÃÄÄ attacker_server.py
³   ÀÄÄ generate_malicious_certificate.py
ÃÄÄ client/
³   ÃÄÄ __init__.py
³   ÀÄÄ client.py
ÃÄÄ ecc/
³   ÃÄÄ __init__.py
³   ÃÄÄ certificate.json
³   ÃÄÄ ecc_utils.py
³   ÃÄÄ ecdsa.py
³   ÀÄÄ generate_certificate.py
ÃÄÄ server/
³   ÃÄÄ __init__.py
³   ÃÄÄ certificate.pem
³   ÀÄÄ server.py
ÀÄÄ utils/
    ÃÄÄ __init__.py
    ÀÄÄ certificate.py
```

---

## Setup and Usage

### 1. Clone the repo

```bash
git clone htttps://Jashanveer-Singh/cryptographic_failure.git
```
### 2. Generate Certificate

You must prepare a certificate configuration file in JSON format ([see Example](#Example-Certificate.json)).

```bash
python ecc/generate_certificate.py <config_file_path> <output_certificate_pem_file_path> <output_public_key_json_file_path>
```

* `<config_file_path>`: JSON file with certificate details.
* `<output_certificate_pem_file_path>`: Output PEM file for the signed certificate (move to `server/` directory as `certificate.pem`).
* `<output_public_key_json_file_path>`: Output JSON file with the public key (move to `client/public_key.json`).

#### Run
```bash
python generate_certificate.py certificate.json signed_certificate.pem public_key.json
```

* make copy of `signed_certificate.pem` in `server/certificate.pem` and `attacker/original_certificate.pem`.
* make copy of `public_key.json` in `client/public_key.json` and `attacker/public_key.json`.

#### Malicious certificate can now be generated using the following command
```bash
python generate_malicious_certificate.py
```

---

### 3. Run the Server

server automatically runs at  `localhost:8080` and serves the valid certificate.

```bash
cd path/to/server
python server.py
```

attacking server automatically runs at `localhost:8081` and serves the malicious certificate.

```bash
cd path/to/attacker
python attacker_server.py
```

---

### 4. Run the Client

Client requests the certificate from the server and verifies it using the public key.

```bash
cd path/to/client

# Normal (vulnerable) mode
python client.py 8080

# Safe mode (verifies curve parameters correctly)
python client.py 8080 -s
```

---

### 5. Attack

if attacker do a MITM attack. He can verify himself because of curve ball vulnerability.
For simplicity demonstration purpose we will ourself send a request to the attack server.
```bash
cd path/to/client

# Normal (vulnerable) mode
python client.py 8081
Attacker Certificate will successfully verify

# Safe mode (verifies curve parameters correctly)
python client.py 8081 -s
Attack fails. Certificate is not valid
```

---

## How the Attack Works

* The client in **normal mode** does **not** verify curve base parameters strictly.
* The attacker crafts a malicious certificate with curve base G' set to the victim's public key Q.
* The client accepts the malicious certificate as valid, demonstrating the CurveBall vulnerability.
* The **safe mode** client performs strict curve parameter verification, preventing the attack.

---

## Example-Certificate.json

Place this file in ecc/certificate.json or provide it as input during certificate generation:
```bash
{
  "server_name": "localhost",
  "curve": {
    "name": "secp256k1",
    "a": "0x00",
    "b": "0x07",
    "p": 115792089237316195423570985008687907853269984665640564039457584007908834671663,
    "n": 115792089237316195423570985008687907852837564279074904382605163141518161494337,
    "Gx": 55066263022277343669578718895168534326250603453777594175500187360389116729240,
    "Gy": 32670510020758816978083085130507043184471273380659243275938904335757337482424
  },
  "public_key": {
    "x": 20599436666767295889415985834645021663614819745695979137505932762683386682188,
    "y": 26501100631878754465881482792096558283890443840859593764123630308831432500483
  },
  "signature_algorithm": "ECDSA-SHA256",
  "valid_from": "2025-01-01T00:00:00Z",
  "valid_to": "2035-01-01T00:00:00Z",
  "other_info": "This certificate is for a cryptographic failure vulnerability project on localhost."
}
```

---

## Notes

* This project is for educational and research purposes only.
* Do **not** use the attack techniques against any unauthorized systems.
* Understand cryptographic failures like CurveBall to improve security and validation in software.
