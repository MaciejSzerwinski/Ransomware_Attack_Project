# Ransomware Attack Simulation Project

> **Warning**: This project is intended solely for educational and testing purposes in a secure, isolated environment (e.g., controlled lab environment or virtual machine). Do not execute on any production or personal device.

## Overview

This project demonstrates the basic functionality of a ransomware attack by encrypting files within a directory. It uses the Python `cryptography` library to handle encryption and decryption, and includes utilities to simulate ransomware behavior, helping users understand the mechanics behind file encryption in a controlled setting.

## Project Structure

- **autorun.py**: Main script for file encryption.
- **encryption_key.key**: Stores the encryption key generated during the encryption process.
- **salt.salt**: Contains a salt value for enhanced security when deriving keys from passwords.
- **cos.txt**: A sample file to showcase encryption functionality.
- **README.md**: Project documentation.
- **logo.jpg**: Image asset, potentially used for branding or UI demonstration.
- **dist/autorun.exe**: Standalone executable of `autorun.py`, created for testing.

## Requirements

To run this project, you will need Python 3 installed. Install the necessary packages with:
```bash
pip install cryptography
