"""
Author: Hiroshi Thomas
Date: 5/17/24
Description: Python Decryption Tool that sends host info and key via discord webhook

This script is licensed under the MIT License.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import os
import socket
from uuid import getnode as get_mac
from tkinter import Tk, filedialog, simpledialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def decrypt_file(file_path: str, key: bytes):
    with open(file_path, 'rb') as file:
        iv = file.read(16)
        ciphertext = file.read()
    
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    with open(file_path, 'wb') as file:
        file.write(plaintext)

def decrypt_directory(directory_path: str, key: bytes):
    key = key[:32]  # Ensure the key is the correct length for AES
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            decrypt_file(file_path, key)

def browse_folder():
    root = Tk()
    root.withdraw()
    folder_path = filedialog.askdirectory()
    return folder_path

def get_key():
    root = Tk()
    root.withdraw()
    key = simpledialog.askstring("Input", "Enter the decryption key:", show='*')
    return key

def main():
    key = get_key()
    if key:
        key_bytes = key.encode()[:32]  # Ensure key is 32 bytes for AES

        folder_path = browse_folder()
        if folder_path:
            decrypt_directory(folder_path, key_bytes)
            print(f"Directory {folder_path} decrypted successfully.")
        else:
            print("No folder selected.")
    else:
        print("No key entered.")

if __name__ == "__main__":
    main()
