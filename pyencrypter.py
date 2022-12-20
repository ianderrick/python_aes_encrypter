import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class App:
    def __init__(self, master):
        self.master = master
        self.init_widgets()
    
    def init_widgets(self):
        self.file_label = tk.Label(self.master, text='Select a file:')
        self.file_label.pack()

        self.file_button = tk.Button(self.master, text='Browse...', command=self.select_file)
        self.file_button.pack()

        self.passphrase_label = tk.Label(self.master, text='Enter a passphrase:')
        self.passphrase_label.pack()

        self.passphrase_entry = tk.Entry(self.master, show='*')
        self.passphrase_entry.pack()

        self.encrypt_button = tk.Button(self.master, text='Encrypt', command=self.encrypt)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(self.master, text='Decrypt', command=self.decrypt)
        self.decrypt_button.pack()
    
    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        self.file_label.config(text=os.path.basename(self.file_path))

    def encrypt(self):
        passphrase = self.passphrase_entry.get()
        if not passphrase:
            messagebox.showerror('Error', 'Please enter a passphrase')
            return

# Generate a key from the passphrase using PBKDF2
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))

# Encrypt the file using the generated key
        fernet = Fernet(key)
        with open(self.file_path, 'rb') as f:
            data = f.read()
        encrypted_data = fernet.encrypt(data)

# Save the encrypted file
        encrypted_file_path = self.file_path + '.encrypted'
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)

        messagebox.showinfo('Success', 'File encrypted successfully')

    def decrypt(self):
        passphrase = self.passphrase_entry.get()
        if not passphrase:
