# DataWipe – Secure Data Wiping & Certificate Verification System

## Overview

DataWipe is a Python-based desktop application designed to securely erase storage devices using industry-standard data wiping techniques. It provides an intuitive graphical user interface (GUI) for selecting storage devices, performing secure wipe operations, generating verification logs, and issuing PDF certificates with QR code support. The application also supports optional blockchain-based certificate hash storage for integrity verification.

---

## Features

* Secure data wiping of storage devices
* Automatic storage device detection
* User-friendly graphical interface (PySide6)
* Wipe operation logging
* PDF certificate generation
* QR code generation for certificate verification
* SHA-256 hash generation
* Optional blockchain integration for certificate integrity

---

## Project Structure

```
DataWipe-final_app/
│── gui_app.py                 # Main GUI application
│── device_detection1.py       # Detect available storage devices
│── wiper.py                   # Secure data wipe logic
│── logger_module.py           # Logging functionality
│── certificate_module.py      # PDF & QR certificate generation
│── blockchain_module.py       # Blockchain integration (optional)
│── requirements.txt
│── .gitignore
│── README.md
└── .env.example
```

---

## Requirements

* Python 3.10 or later
* Windows (Recommended)
* Administrator privileges for disk wiping

---

## Installation

Clone the repository:

```bash
git clone https://github.com/SARTHAKSHEWALE05/DataWipe.git
cd DataWipe
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it:

Windows (PowerShell)

```powershell
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Configuration

Create a `.env` file from the provided template:

```
cp .env.example .env
```

or manually create a `.env` file and fill in the required blockchain credentials.

> **Important:** Never commit your `.env` file to GitHub.

---

## Running the Application

```bash
python gui_app.py
```

---

## How It Works

1. Detect connected storage devices.
2. Select the target device.
3. Perform secure data wiping.
4. Generate a wipe log.
5. Generate a PDF certificate.
6. Compute a SHA-256 hash of the certificate.
7. Optionally store the hash on the blockchain.

---

## Blockchain Integration

Blockchain support is optional.

To enable blockchain functionality, provide:

* Smart Contract Address
* Contract ABI (`contract_abi.json`)
* Wallet Private Key
* Wallet Address
* Alchemy RPC URL

If blockchain credentials or ABI are unavailable, the application can still perform secure wiping and certificate generation.

---

## Security Notes

* Never upload your `.env` file.
* Never expose your private key.
* Do not commit generated certificates or local logs.
* Run wipe operations only with Administrator privileges.

---

## Future Improvements

* Multiple wiping algorithms (DoD 5220.22-M, Gutmann, NIST)
* Real-time progress monitoring
* Multi-threaded wiping
* Cloud backup of certificates
* Database integration
* Cross-platform support

---

## Disclaimer

This software performs irreversible data deletion. Use it carefully and only on devices intended for secure erasure. The developers are not responsible for any accidental data loss.

---

## License

This project is intended for educational and research purposes.
