import tkinter as tk
from tkinter import filedialog
from PIL import Image, ImageTk 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode, urlsafe_b64decode
import binascii
import os


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key

def convert_and_display(encryption_func, encoding_type):
    password = key_entry.get().encode('utf-8')
    salt = b'salt_123'
    key = derive_key(password, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16))
    encryptor = cipher.encryptor()
    plaintext = text_entry.get("1.0", tk.END).strip().encode('utf-8')
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    if encoding_type == "Base64":
        result = urlsafe_b64encode(ciphertext).decode('utf-8')
    elif encoding_type == "Hex":
        result = ciphertext.hex()
    elif encoding_type == "Binary":
        result = " ".join(format(byte, '08b') for byte in ciphertext)
    elif encoding_type == "Decimal":
        result = " ".join(str(byte) for byte in ciphertext)
    else:
        result = "Unsupported encoding"


def encrypt_text():
    selected_encoding = encoding_var.get()
    convert_and_display(encrypt_text, selected_encoding)
    password = key_entry.get().encode('utf-8')
    salt = b'salt_123'
    key = derive_key(password, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16))
    encryptor = cipher.encryptor()
    plaintext = text_entry.get("1.0", tk.END).strip().encode('utf-8')
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    if selected_encoding == "Base64":
        encrypted_text = urlsafe_b64encode(ciphertext).decode('utf-8')
    elif selected_encoding == "Hex":
        encrypted_text = ciphertext.hex()
    elif selected_encoding == "Binary":
        encrypted_text = " ".join(format(byte, '08b') for byte in ciphertext)
    elif selected_encoding == "Decimal":
        encrypted_text = " ".join(str(byte) for byte in ciphertext)
    else:
        encrypted_text = "Unsupported encoding"

    result_window("Encrypted Text", encrypted_text, border_color="red")


def decrypt_text():
    selected_encoding = encoding_var.get()
    convert_and_display(decrypt_text, selected_encoding)
    password = key_entry.get().encode('utf-8')
    salt = b'salt_123'
    key = derive_key(password, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16))
    decryptor = cipher.decryptor()
    encrypted_text = text_entry.get("1.0", tk.END).strip().encode('utf-8')

    if selected_encoding == "Base64":
        ciphertext = urlsafe_b64decode(encrypted_text)
    elif selected_encoding == "Hex":
        ciphertext = binascii.unhexlify(encrypted_text)
    elif selected_encoding == "Binary":
        ciphertext = bytes(int(b, 2) for b in encrypted_text.split())
    elif selected_encoding == "Decimal":
        ciphertext = bytes(int(b) for b in encrypted_text.split())
    else:
        result_window("Unsupported encoding", "", border_color="gray")
        return

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    result_window("Decrypted Text", plaintext.decode('utf-8'), border_color="green")


def open_text_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'r') as file:
            text = file.read()
            text_entry.delete("1.0", tk.END)
            text_entry.insert(tk.END, text)


def save_text_option():
    result_text = text_entry.get("1.0", tk.END).strip()
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write(result_text)

def result_window(title, result, border_color):
    result_window = tk.Toplevel(root)
    result_window.title(title)
    result_window.configure(borderwidth=5, relief=tk.SOLID)
    result_window.geometry("400x300")
    result_window.configure(bg=border_color)

    result_text = tk.Text(result_window, wrap=tk.WORD)
    result_text.insert(tk.END, result)
    result_text.pack(pady=10)


def reset_text():
    text_entry.delete("1.0", tk.END)
    key_entry.delete(0, tk.END)

root = tk.Tk()
root.title("AES Encryption/Decryption Tool")
root.geometry("400x520")

image_path = os.path.join(os.path.dirname(__file__), 'src', 'logo.png')
logo_image = Image.open(image_path)
logo_image = logo_image.resize((100, 100))
root.logo_icon = ImageTk.PhotoImage(logo_image)
root.iconphoto(True, root.logo_icon)
root.logo_label = tk.Label(root, image=root.logo_icon)
root.logo_label.pack(side="top", pady=10)

def show_context_menu(event):
    context_menu.post(event.x_root, event.y_root)

context_menu = tk.Menu(root, tearoff=0)
context_menu.add_command(label="Cut", command=lambda: text_entry.event_generate("<<Cut>>"))
context_menu.add_command(label="Copy", command=lambda: text_entry.event_generate("<<Copy>>"))
context_menu.add_command(label="Paste", command=lambda: text_entry.event_generate("<<Paste>>"))
context_menu.add_command(label="Select All", command=lambda: text_entry.tag_add(tk.SEL, "1.0", tk.END))

text_entry = tk.Text(root) 
text_entry.bindtags((text_entry, result_window, "all"))
text_entry.bind_class("all", "<Button-2>", show_context_menu)

menu_bar = tk.Menu(root)
root.config(menu=menu_bar)

options_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Options", menu=options_menu)
options_menu.add_command(label="Open Text File", command=open_text_file)
options_menu.add_command(label="Save Text", command=save_text_option)

text_entry = tk.Text(root, height=10, width=40, wrap=tk.WORD)
text_entry.pack()

key_label = tk.Label(root, text="Enter Secret Key:")
key_label.pack(pady=5)

key_entry = tk.Entry(root, show="*")
key_entry.pack(pady=5)

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_text)
encrypt_button.pack(pady=5)

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_text)
decrypt_button.pack(pady=5)

reset_button = tk.Button(root, text="Reset", command=reset_text)
reset_button.pack(pady=5)

encoding_var = tk.StringVar(root)
encoding_var.set("Base64")

encoding_label = tk.Label(root, text="Encoding Type")
encoding_label.pack(pady=5)

encoding_menu = tk.OptionMenu(root, encoding_var, "Base64", "Hex", "Binary", "Decimal")
encoding_menu.pack(pady=5)

root.mainloop()