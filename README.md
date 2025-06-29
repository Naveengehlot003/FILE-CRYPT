# 🔐 FILE-CRYPT – GUI File Encryptor & Decryptor

FILE-CRYPT is a secure, user-friendly Python GUI application that allows users to *encrypt* and *decrypt* files using password-based AES encryption (via Fernet). It also logs all activities and sends real-time email alerts for encryption/decryption events or failures.

## 🛡️ Features

* ✅ *Encrypt/Decrypt Multiple Files* with password protection
* ✅ *AES-based encryption (Fernet)*
* ✅ *Dark-themed GUI* using Tkinter
* ✅ *Real-time Logs* in both GUI and matrixcrypt_log.txt
* ✅ *Email Alerts* on every encryption/decryption event
* ✅ *Cross-platform* (Windows/Linux)

---

## 📁 Project Structure


MatrixCrypt/
│
├── filecrypt_gui.py          # Main application script
├── matrixcrypt_log.txt       # Activity logs (auto-generated)
├── README.md                 # Project documentation


---

## 🚀 Getting Started

### 🔧 Requirements

* Python 3.7+
* Dependencies:

  * cryptography
  * tkinter (comes with Python)
  * smtplib and email (standard libraries)

### 📦 Installation

bash
pip install cryptography


### ▶️ Run the App

bash
python filecrypt_gui.py


---

## 🛠️ How It Works

1. Launch the GUI and choose *Encrypt* or *Decrypt*.
2. Select one or more files.
3. Enter a custom password (used to generate an encryption key).
4. The output files will be saved with _encrypted or _decrypted suffixes.
5. Logs and email alerts are automatically generated.

---

## 📧 Email Alert Configuration

Located at the top of filecrypt_gui.py:

python
EMAIL_SENDER = "youremail@gmail.com"
EMAIL_RECEIVER = "recipient@gmail.com"
EMAIL_PASSWORD = "your_app_password"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587


> ⚠️ *Important:* Use an [App Password](https://support.google.com/accounts/answer/185833?hl=en) if using Gmail with 2FA.

---

## 📝 Log Output Example

* Log file: matrixcrypt_log.txt


[2025-06-29 20:05:22] [+] Encrypted: myfile.txt -> myfile_encrypted.txt
[2025-06-29 20:06:10] [+] Decrypted: myfile_encrypted.txt -> myfile_encrypted_decrypted.txt


---

## 🔒 Security Notes

* Password-based key is padded to meet Fernet requirements.
* Files are never uploaded or shared — processed locally.
* Email alerts help detect unauthorized or suspicious file operations.

---

## 🧑‍💻 Author

*Naveen Gehlot*
BCA Cybersecurity Student | Developer | Ethical Hacker
[LinkedIn](https://www.linkedin.com/in/naveen-gehlot-214663260/ ) • [GitHub](https://github.com/Naveengehlot003
) • [Email](#)

---
