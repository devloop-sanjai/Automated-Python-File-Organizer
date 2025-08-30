from dotenv import load_dotenv
import os
print("Current working directory:", os.getcwd())
import shutil
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
import random
import hashlib
from cryptography.fernet import Fernet
import smtplib
from email.mime.text import MIMEText
import socket
import platform
import datetime
import logging


# ------------------------------
# Load Environment Variables
# ------------------------------
load_dotenv()


EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER")
APP_PASSWORD = os.getenv("APP_PASSWORD")
AUTH_PASSWORD = os.getenv("AUTH_PASSWORD")
print("DEBUG - AUTH_PASSWORD from .env:", AUTH_PASSWORD)

# ------------------------------
# Setup Logging
# ------------------------------
logging.basicConfig(
    filename="organizer.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ------------------------------
# Persistent AES Key
# ------------------------------
KEY_FILE = "encryption.key"
if os.path.exists(KEY_FILE):
    ENCRYPTION_KEY = open(KEY_FILE, "rb").read()
else:
    ENCRYPTION_KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(ENCRYPTION_KEY)
cipher = Fernet(ENCRYPTION_KEY)

# ------------------------------
# MFA Verification
# ------------------------------
def verify_user():
    password = simpledialog.askstring("Authentication", "Enter Password:", show="*")
    if password != AUTH_PASSWORD:
        messagebox.showerror("Access Denied", "Incorrect password!")
        logging.warning("Authentication failed: wrong password")
        return False

    otp = str(random.randint(100000, 999999))
    messagebox.showinfo("MFA Code", f"Your OTP is: {otp}")

    entered_otp = simpledialog.askstring("Authentication", "Enter OTP:")
    if entered_otp != otp:
        messagebox.showerror("Access Denied", "Incorrect OTP!")
        logging.warning("Authentication failed: wrong OTP")
        return False

    logging.info("Authentication successful")
    return True

# ------------------------------
# Email Alert
# ------------------------------
def send_email_alert(file_path, detection_reason="Filename contains 'virus'"):
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        hostname = socket.gethostname()
        user = os.getlogin()
        os_info = f"{platform.system()} {platform.release()}"

        file_hash = "N/A"
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

        body = f"""
🚨 Malware Detected and Quarantined 🚨

File Path     : {file_path}
SHA256 Hash   : {file_hash}
Detected At   : {timestamp}
Detection Type: {detection_reason}
Action Taken  : File encrypted & moved to Virus folder
System Info   : {os_info} (Host: {hostname}, User: {user})
"""

        msg = MIMEText(body)
        msg["Subject"] = "⚠ Malware Alert - File Quarantined"
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECEIVER

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_SENDER, APP_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())

        logging.info(f"Email sent successfully for file: {file_path}")
    except Exception as e:
        logging.error(f"Email failed: {e}")

# ------------------------------
# Quarantine
# ------------------------------
def quarantine_file(file_path, log_box, log_file):
    virus_dir = os.path.join(os.path.dirname(file_path), "Virus")
    os.makedirs(virus_dir, exist_ok=True)

    with open(file_path, "rb") as f:
        encrypted_data = cipher.encrypt(f.read())

    encrypted_path = os.path.join(virus_dir, os.path.basename(file_path) + ".enc")
    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)

    os.remove(file_path)

    log_message = f" Malware detected and quarantined: {file_path}\n"
    log_box.insert("end", log_message)
    log_file.write(log_message)
    logging.warning(log_message.strip())

    send_email_alert(file_path)

# ------------------------------
# Malware Check (Dummy)
# ------------------------------
def is_malware(file_path):
    return "virus" in os.path.basename(file_path).lower()

# ------------------------------
# Organize Files
# ------------------------------
def organize_files(directory, log_box):
    global last_moved
    log_file_path = os.path.join(directory, "log.txt")
    last_moved = []
    moved_files_logged = set()

    excluded_folders = {"log.txt", "Virus", "Images", "Videos", "Audios", "Documents", "Others"}

    with open(log_file_path, "a", encoding="utf-8") as log_file:
        for entry in os.scandir(directory):
            file_path = entry.path
            filename = entry.name

            if filename in excluded_folders or filename.endswith(".enc"):
                continue

            if file_path in moved_files_logged:
                continue

            if entry.is_file():
                ext = filename.split(".")[-1].lower()

                if is_malware(file_path):
                    quarantine_file(file_path, log_box, log_file)
                else:
                    if ext in ["jpg", "png", "jpeg", "gif"]:
                        folder = "Images"
                    elif ext in ["mp4", "mkv", "avi", "mov"]:
                        folder = "Videos"
                    elif ext in ["mp3", "wav", "aac", "ogg"]:
                        folder = "Audios"
                    elif ext in ["pdf", "docx", "doc", "txt", "pptx", "xlsx"]:
                        folder = "Documents"
                    else:
                        folder = "Others"

                    folder_path = os.path.join(directory, folder)
                    os.makedirs(folder_path, exist_ok=True)
                    new_path = os.path.join(folder_path, filename)

                    shutil.move(file_path, new_path)
                    last_moved.append((new_path, file_path))

                    log_message = f"Moved {filename} to {folder}\n"
                    log_box.insert("end", log_message)
                    log_file.write(log_message)
                    logging.info(log_message.strip())
                    moved_files_logged.add(file_path)

# ------------------------------
# Undo
# ------------------------------
def undo_move():
    global last_moved
    if not last_moved:
        log_box.insert("end", "No actions to undo.\n")
        return

    for new_path, old_path in last_moved:
        if os.path.exists(new_path):
            shutil.move(new_path, old_path)
            log_box.insert("end", f"Restored {os.path.basename(new_path)}\n")
            logging.info(f"Restored {new_path}")
    last_moved = []

# ------------------------------
# Restore from Virus
# ------------------------------
def restore_from_virus():
    if not verify_user():
        return

    virus_dir = filedialog.askdirectory(title="Select Virus Folder")
    if not virus_dir:
        return

    restored_dir = os.path.join(virus_dir, "Restored")
    os.makedirs(restored_dir, exist_ok=True)

    for filename in os.listdir(virus_dir):
        if filename.endswith(".enc"):
            enc_path = os.path.join(virus_dir, filename)
            with open(enc_path, "rb") as f:
                decrypted_data = cipher.decrypt(f.read())

            restored_path = os.path.join(restored_dir, filename.replace(".enc", ""))
            with open(restored_path, "wb") as f:
                f.write(decrypted_data)

            log_box.insert("end", f"✅ Restored from Virus: {restored_path}\n")
            logging.info(f"Restored file from Virus: {restored_path}")

# ------------------------------
# Tkinter UI
# ------------------------------
root = tk.Tk()
root.title("File Organizer with Malware Quarantine")
root.geometry("650x450")

frame = tk.Frame(root)
frame.pack(pady=20)

choose_button = tk.Button(frame, text="Choose Folder", command=lambda: choose_folder())
choose_button.grid(row=0, column=0, padx=10)

undo_button = tk.Button(frame, text="Undo", command=undo_move)
undo_button.grid(row=0, column=1, padx=10)

restore_button = tk.Button(frame, text="Restore from Virus", command=restore_from_virus)
restore_button.grid(row=0, column=2, padx=10)

log_box = tk.Text(root, height=15, width=80)
log_box.pack(pady=10)

last_moved = []

def choose_folder():
    if not verify_user():
        return
    directory = filedialog.askdirectory()
    if directory:
        log_box.delete("1.0", "end")
        log_box.insert("end", f"\nOrganizing folder: {directory}\n")
        organize_files(directory, log_box)

root.mainloop()
