import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import numpy as np
import math
import atexit

# Define a fixed key for encryption and decryption using Hill cipher
HILL_KEY = np.array([[3, 10], [20, 9]])

class StartDialog:
    def __init__(self, root):
        self.root = root
        self.root.title("Choose Role")
        self.root.geometry("300x200")
        self.root.resizable(False, False)

        ttk.Label(root, text="Choose your role:", font=("Arial", 12)).pack(pady=10)

        self.role_var = tk.StringVar(value="server")

        ttk.Radiobutton(root, text="Server", value="server", variable=self.role_var, command=self.close_window).pack(pady=5)
        ttk.Radiobutton(root, text="Client", value="client", variable=self.role_var, command=self.close_window).pack(pady=5)

        ttk.Label(root, text="Choose cipher technique:", font=("Arial", 12)).pack(pady=10)
        self.cipher_var = tk.StringVar(value="hill")

        ttk.OptionMenu(root, self.cipher_var, "hill", "hill", "vigenere").pack(pady=5)

    def close_window(self):
        self.root.destroy()

class CustomScrolledText(scrolledtext.ScrolledText):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.config(font=("Helvetica", 10, "bold"))
        self.config(bg="gray")  # Change background color to gray
        self.config(borderwidth=0)   # Remove border
        self.config(relief=tk.FLAT)  # Set relief to FLAT for soft edges

class ChatApp:
    def __init__(self, root, role, cipher_technique):
        self.root = root
        self.root.title("Secure Chat App")
        self.root.geometry("600x400")
        self.root.configure(bg="black")  # Set background color to black
        self.root.resizable(True, True)

        self.style = ttk.Style()
        self.style.theme_use("clam")  # Change the theme to a dark theme
        self.style.configure('TButton', background='darkblue')  # Set button background color to dark blue

        # Title box specifying client or server
        self.title_label = ttk.Label(root, text="Server" if role == "server" else "Client", font=("Arial", 16))
        self.title_label.pack(pady=10)

        self.message_entry = ttk.Entry(root, width=50)
        self.message_entry.pack(pady=10)

        self.send_button = ttk.Button(root, text="Send", command=self.send_message)
        self.send_button.pack(pady=10)

        self.chat_box = CustomScrolledText(root, width=50, height=20)
        self.chat_box.pack(pady=10)

        self.show_last_normal_button = ttk.Button(root, text="Show Last Normal Message", command=self.show_last_normal_message)
        self.show_last_normal_button.pack(pady=10)
        self.show_last_normal_button.config(state="disabled")

        self.server_socket = None
        self.client_socket = None
        self.last_normal_message = ""

        self.is_server = (role == "server")
        self.cipher_technique = cipher_technique

        if self.is_server:
            self.start_server()
        else:
            self.start_client()

        atexit.register(self.on_exit)

    def on_exit(self):
        if self.is_server:
            self.server_socket.close()
        elif self.client_socket:
            self.client_socket.close()

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(("127.0.0.1", 12345))
        self.server_socket.listen()

        print("Server listening on port 12345")

        client_socket, client_address = self.server_socket.accept()
        print("Connection from", client_address)

        self.client_socket = client_socket

        threading.Thread(target=self.receive_messages).start()

    def start_client(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(("127.0.0.1", 12345))

        threading.Thread(target=self.receive_messages).start()

    def send_message(self):
        message = self.message_entry.get()
        self.message_entry.delete(0, tk.END)
        self.client_socket.send(message.encode())

        # Encrypt the message and send it
        encrypted_message = self.encrypt(message)
        self.client_socket.send(encrypted_message.encode())

        # Display the encrypted message in the chat box
        self.display_message("You (Encrypted)", encrypted_message)

    def receive_messages(self):
        while True:
            try:
                received_normal_message = self.client_socket.recv(1024).decode()
                if not received_normal_message:
                    break  # Handle client disconnect

                # Receive the encrypted message
                received_encrypted_message = self.client_socket.recv(1024).decode()
                if not received_encrypted_message:
                    break  # Handle client disconnect

                # Store the last normal message received
                self.last_normal_message = received_normal_message

                # Display the encrypted message in the chat box
                self.display_message("Client (Encrypted)", received_encrypted_message)

                # Enable the button to show the last normal message
                self.show_last_normal_button.config(state="normal")
            except ConnectionResetError:
                break  # Handle unexpected disconnection

    def display_message(self, sender, message):
        self.chat_box.insert(tk.END, f"{sender}: {message}\n")
        self.chat_box.see(tk.END)

    def encrypt(self, message):
        if self.cipher_technique == "hill":
            return self.encrypt_hill_cipher(message)
        elif self.cipher_technique == "vigenere":
            key = self.convert_hill_key_to_string()
            return self.encrypt_vigenere_cipher(message, key)

    def encrypt_hill_cipher(self, message):
        message = message.upper().replace(" ", "")
        message_len = len(message)

        while len(message) % len(HILL_KEY) != 0:
            message += "X"

        message_numbers = [ord(char) - ord('A') for char in message]
        message_matrix = np.array(message_numbers).reshape(-1, len(HILL_KEY))

        encrypted_matrix = np.dot(message_matrix, HILL_KEY) % 26
        encrypted_message = "".join([chr(num + ord('A')) for num in encrypted_matrix.flatten()])

        return encrypted_message

    def encrypt_vigenere_cipher(self, message, key):
        message = message.upper().replace(" ", "")
        key = key.upper().replace(" ", "")
        encrypted_message = ""

        for i in range(len(message)):
            char = message[i]
            key_char = key[i % len(key)]
            encrypted_char = chr(((ord(char) - 65) + (ord(key_char) - 65)) % 26 + 65)
            encrypted_message += encrypted_char

        return encrypted_message

    def convert_hill_key_to_string(self):
        key_str = ""
        for row in HILL_KEY:
            for num in row:
                key_str += chr(num + ord('A'))
        return key_str

    def show_last_normal_message(self):
        messagebox.showinfo("Last Normal Message", self.last_normal_message)

def main():
    start_root = tk.Tk()
    start_dialog = StartDialog(start_root)
    start_root.mainloop()

    role = start_dialog.role_var.get()
    cipher_technique = start_dialog.cipher_var.get()

    root = tk.Tk()
    app = ChatApp(root, role, cipher_technique)
    root.mainloop()

if __name__ == "__main__":
    main()
