from tkinter import scrolledtext
import tkinter as tk
import string
import random

def create_random_key(size):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(size))

def encrypt_with_probabilistic_cipher(message, key):
    encrypted_message, offsets = [], []

    for char, k in zip(message, key):
        offset = random.randint(1, 20)
        offsets.append(offset)

        encrypted_char = chr((ord(char) + ord(k) + offset) % 256)
        encrypted_message.append(encrypted_char)

    return ''.join(encrypted_message), offsets

def decrypt_with_probabilistic_cipher(encrypted_message, key, offsets):
    decrypted_message = [chr((ord(enc_char) - ord(k) - offset) % 256) for enc_char, k, offset in zip(encrypted_message, key, offsets)]
    return ''.join(decrypted_message)

class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Вероятностный шифр")

        tk.Label(self.root, text="Введите текст для шифрования:").pack(pady=5)
        self.input_text = tk.Entry(self.root, width=50)
        self.input_text.pack(pady=5)

        self.button_generate_key = tk.Button(self.root, text="Сгенерировать ключ", command=self.generate_key)
        self.button_generate_key.pack(pady=5)

        self.key_label = tk.Label(self.root, text="Ключ: Не сгенерирован")
        self.key_label.pack(pady=5)

        self.text_display = scrolledtext.ScrolledText(self.root, width=50, height=10)
        self.text_display.pack(pady=5)
        self.text_display.config(state=tk.DISABLED)

        self.button_encrypt = tk.Button(self.root, text="Зашифровать", command=self.perform_encryption)
        self.button_encrypt.pack(pady=10)

        self.button_decrypt = tk.Button(self.root, text="Расшифровать", command=self.perform_decryption)
        self.button_decrypt.pack(pady=10)

        self.saved_key = None
        self.saved_offsets = None
        self.saved_encrypted_text = None

    def generate_key(self):
        plaintext = self.input_text.get()
        if not plaintext:
            self.text_display.config(state=tk.NORMAL)
            self.text_display.delete(1.0, tk.END)
            self.text_display.insert(tk.END, "Введите текст для генерации ключа.")
            self.text_display.config(state=tk.DISABLED)
            return

        key = create_random_key(len(plaintext))
        self.saved_key = key
        self.key_label.config(text=f'Ключ: {key}')

    def perform_encryption(self):
        if self.saved_key is None:
            self.text_display.config(state=tk.NORMAL)
            self.text_display.delete(1.0, tk.END)
            self.text_display.insert(tk.END, "Сначала сгенерируйте ключ!")
            self.text_display.config(state=tk.DISABLED)
            return

        plaintext = self.input_text.get()
        if not plaintext:
            self.text_display.config(state=tk.NORMAL)
            self.text_display.delete(1.0, tk.END)
            self.text_display.insert(tk.END, "Введите текст для шифрования.")
            self.text_display.config(state=tk.DISABLED)
            return

        ciphertext, offsets = encrypt_with_probabilistic_cipher(plaintext, self.saved_key)
        self.saved_offsets = offsets  
        self.saved_encrypted_text = ciphertext  

        self.update_display(ciphertext, is_encrypted=True)

    def perform_decryption(self):
        if self.saved_key is None or self.saved_offsets is None or self.saved_encrypted_text is None:
            self.text_display.config(state=tk.NORMAL)
            self.text_display.delete(1.0, tk.END)
            self.text_display.insert(tk.END, "Зашифрованный текст не найден или ключ не сгенерирован.")
            self.text_display.config(state=tk.DISABLED)
            return

        encrypted_message = self.saved_encrypted_text  
        if not encrypted_message:
            self.text_display.config(state=tk.NORMAL)
            self.text_display.delete(1.0, tk.END)
            self.text_display.insert(tk.END, "Зашифрованный текст пуст.")
            self.text_display.config(state=tk.DISABLED)
            return

        decrypted_text = decrypt_with_probabilistic_cipher(encrypted_message, self.saved_key, self.saved_offsets)
        self.update_display(decrypted_text, is_encrypted=False)

    def update_display(self, text, is_encrypted=True):
        self.text_display.config(state=tk.NORMAL)
        self.text_display.delete(1.0, tk.END)

        if is_encrypted:
            self.text_display.insert(tk.END, "Зашифрованный текст:\n")
        else:
            self.text_display.insert(tk.END, "Расшифрованный текст:\n")

        self.text_display.insert(tk.END, text)
        self.text_display.config(state=tk.DISABLED)

root_window = tk.Tk()
app = CipherApp(root_window)
root_window.geometry("600x500")
root_window.mainloop()
