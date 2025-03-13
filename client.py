import socket
import threading
import rsa
import tkinter as tk
from tkinter import simpledialog, scrolledtext

client_public, client_private = rsa.newkeys(1024)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 55555))

server_public = None
nickname = None
password = ""

def ask_for_credentials():
    global nickname, password

    login_window = tk.Tk()
    login_window.withdraw()

    nickname = simpledialog.askstring("Nickname", "Enter your nickname:", parent=login_window)

    if not nickname:
        exit()

    if nickname.lower() == "admin":
        password = simpledialog.askstring("Admin Login", "Enter admin password:", show="*", parent=login_window)

# gui
root = tk.Tk()
root.withdraw()
root.title("Encrypted Chat")

chat_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled')
chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

input_area = tk.Entry(root)
input_area.pack(fill=tk.X, padx=10, pady=5)

def receive():
    global server_public
    while True:
        try:
            message = client.recv(1024)
            if not message:
                break

            try:
                text = message.decode('utf-8')
            except:
                text = ""

            if text == "NICK":
                client.send(nickname.encode('utf-8'))
            elif text == "PASS":
                client.send(password.encode('utf-8'))
            elif text == "REFUSE":
                show_error("Connection refused: wrong admin password.")
                client.close()
                exit()
            elif text == "BANNED":
                show_error("You are banned from this server.")
                client.close()
                exit()
            elif text == "NICK_IN_USE":
                show_error("Nickname already in use. Please choose another one.")
                client.close()
                exit()
            else:
                if server_public is None:
                    try:
                        server_public = rsa.PublicKey.load_pkcs1(message)
                        client.send(client_public.save_pkcs1("PEM"))
                    except:
                        client.close()
                        break
                else:
                    try:
                        decrypted_message = rsa.decrypt(message, client_private).decode('utf-8')
                        chat_area.config(state='normal')
                        chat_area.insert(tk.END, f"{decrypted_message}\n")
                        chat_area.config(state='disabled')
                        chat_area.yview(tk.END)
                    except:
                        pass
        except:
            break

def send_message(event=None):
    message = input_area.get()
    if message and server_public:
        encrypted_msg = rsa.encrypt(message.encode('utf-8'), server_public)
        client.send(encrypted_msg)
        input_area.delete(0, tk.END)

input_area.bind("<Return>", send_message)

def show_error(message):
    error_window = tk.Tk()
    error_window.withdraw()
    tk.messagebox.showerror("Error", message)

ask_for_credentials() # ask for username
root.deiconify() # then show chat window

receive_thread = threading.Thread(target=receive)
receive_thread.start()
root.mainloop()
