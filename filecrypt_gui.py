import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, scrolledtext
from cryptography.fernet import Fernet
from datetime import datetime
import smtplib
from email.mime.text import MIMEText

# ====== Email Configuration ======
EMAIL_SENDER = "your_email@example.com"
EMAIL_RECEIVER = "receiver_email@example.com"
EMAIL_PASSWORD = "your_email_password"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
# ==================================

def generate_key(password: str) -> bytes:
    return base64.urlsafe_b64encode(password.encode('utf-8').ljust(32, b'0'))

def send_email(subject: str, message: str, log_widget):
    try:
        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['From'] = EMAIL_SENDER
        msg['To'] = EMAIL_RECEIVER

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)

        log_widget.insert(tk.END, f"[✉️] Email sent to {EMAIL_RECEIVER}\n")
        log_to_file(f"[✉️] Email sent to {EMAIL_RECEIVER}")
    except Exception as e:
        log_widget.insert(tk.END, f"[!] Failed to send email: {str(e)}\n")
        log_to_file(f"[!] Failed to send email: {str(e)}")

def log_to_file(message: str):
    with open("filecrypt_log.txt", "a") as log:
        log.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")

def encrypt_file(input_path: str, output_path: str, password: str, log_widget):
    key = generate_key(password)
    cipher = Fernet(key)

    try:
        with open(input_path, 'rb') as f:
            data = f.read()
        encrypted = cipher.encrypt(data)
        with open(output_path, 'wb') as f:
            f.write(encrypted)

        msg = f"[+] Encrypted: {input_path} -> {output_path}"
        log_widget.insert(tk.END, msg + "\n")
        log_to_file(msg)
        send_email("FILE-CRYPT Alert - File Encrypted", msg, log_widget)

    except Exception as e:
        err = f"[!] Failed to encrypt {input_path}: {str(e)}"
        log_widget.insert(tk.END, err + "\n")
        log_to_file(err)
        send_email("FILE-CRYPT Alert - Encryption Failed", err, log_widget)

def decrypt_file(input_path: str, output_path: str, password: str, log_widget):
    key = generate_key(password)
    cipher = Fernet(key)

    try:
        with open(input_path, 'rb') as f:
            encrypted_data = f.read()
        decrypted = cipher.decrypt(encrypted_data)
        with open(output_path, 'wb') as f:
            f.write(decrypted)

        msg = f"[+] Decrypted: {input_path} -> {output_path}"
        log_widget.insert(tk.END, msg + "\n")
        log_to_file(msg)
        send_email("FILE-CRYPT Alert - File Decrypted", msg, log_widget)

    except Exception as e:
        err = f"[!] Failed to decrypt {input_path}: {str(e)}"
        log_widget.insert(tk.END, err + "\n")
        log_to_file(err)
        send_email("FILE-CRYPT Alert - Decryption Failed", err, log_widget)

def save_file_path(filename: str, suffix: str):
    base, ext = os.path.splitext(filename)
    return base + suffix + ext

def process_files(action, log_widget):
    files = filedialog.askopenfilenames(title="Select files")
    if not files:
        return

    password = simpledialog.askstring("Password", "Enter password:", show='*')
    if not password:
        return

    for file in files:
        if action == 'encrypt':
            output = save_file_path(file, '_encrypted')
            encrypt_file(file, output, password, log_widget)
        elif action == 'decrypt':
            output = save_file_path(file, '_decrypted')
            decrypt_file(file, output, password, log_widget)

def create_gui():
    root = tk.Tk()
    root.title("FILE-CRYPT")
    root.configure(bg="#000000")
    root.geometry("600x400")

    title = tk.Label(root, text="FILE-CRYPT", font=("Courier New", 24, "bold"), fg="#00FF00", bg="#000000")
    title.pack(pady=10)

    btn_frame = tk.Frame(root, bg="#000000")
    btn_frame.pack(pady=10)

    encrypt_btn = tk.Button(btn_frame, text="Encrypt Files", font=("Courier New", 12), fg="#00FF00", bg="#111111",
                            activebackground="#222222", activeforeground="#00FF00",
                            command=lambda: process_files('encrypt', log_text))
    encrypt_btn.pack(side=tk.LEFT, padx=10)

    decrypt_btn = tk.Button(btn_frame, text="Decrypt Files", font=("Courier New", 12), fg="#00FF00", bg="#111111",
                            activebackground="#222222", activeforeground="#00FF00",
                            command=lambda: process_files('decrypt', log_text))
    decrypt_btn.pack(side=tk.LEFT, padx=10)

    global log_text
    log_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Courier New", 10),
                                         fg="#00FF00", bg="#000000", insertbackground="#00FF00")
    log_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
    log_text.insert(tk.END, "[!] Ready. Select an action above.\n")

    root.mainloop()

if __name__ == '__main__':
    create_gui()
