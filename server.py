import socket
import threading
import rsa
import sqlite3

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

HOST = "127.0.0.1"
PORT = find_free_port()

print(f"Using port: {PORT}")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()
print("Server is listening...")

clients = {}
client_public_keys = {}

banned_users = set()
BAN_FILE = "bans.txt"
DB_FILE = "chat_history.db"

conn = sqlite3.connect(DB_FILE, check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    message TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")
conn.commit()

def log_message_to_db(sender, message):
    cursor.execute("INSERT INTO messages (sender, message) VALUES (?, ?)", (sender, message))
    conn.commit()

def broadcast(message: str, sender_nick: str = None):
    if sender_nick:
        msg = f"{sender_nick}: {message}"
    else:
        msg = message
    log_message_to_db(sender_nick if sender_nick else "System", message)

    for nick, client in clients.items():
        try:
            if nick in client_public_keys:
                encrypted_msg = rsa.encrypt(msg.encode('utf-8'), client_public_keys[nick])
                client.send(encrypted_msg)
            else:
                client.send(msg.encode('utf-8'))
        except:
            continue

def send_private_message(sender: str, recipient: str, message: str):
    if recipient in clients and recipient in client_public_keys:
        msg = f"(Private) {sender} -> {recipient}: {message}"
        encrypted_msg = rsa.encrypt(msg.encode('utf-8'), client_public_keys[recipient])
        clients[recipient].send(encrypted_msg)
        log_message_to_db(sender, f"(PM to {recipient}) {message}")

def kick_user(target: str):
    if target in clients:
        client_to_kick = clients[target]
        if target in client_public_keys:
            kick_msg = rsa.encrypt("You were kicked by the admin.".encode('utf-8'), client_public_keys[target])
            client_to_kick.send(kick_msg)
        client_to_kick.close()
        del clients[target]
        del client_public_keys[target]
        broadcast(f"{target} was kicked by the admin.")

def ban_user(target: str):
    kick_user(target)
    banned_users.add(target)
    with open(BAN_FILE, "a") as f:
        f.write(target + "\n")
    broadcast(f"{target} was banned by the admin.")

SERVER_PUBLIC, SERVER_PRIVATE = rsa.newkeys(1024) #rsa

def handle_client(client: socket.socket, nickname: str):
    while True:
        try:
            encrypted_data = client.recv(1024)
            if not encrypted_data:
                break
            try:
                message = rsa.decrypt(encrypted_data, SERVER_PRIVATE).decode('utf-8')
            except:
                continue

            if message.startswith("/"):
                args = message.split()
                command = args[0].lower()
                
                if command == "/kick" and nickname == "admin":
                    if len(args) < 2:
                        client.send(rsa.encrypt("Usage: /kick <username>".encode('utf-8'), client_public_keys[nickname]))
                    else:
                        kick_user(args[1])

                elif command == "/ban" and nickname == "admin":
                    if len(args) < 2:
                        client.send(rsa.encrypt("Usage: /ban <username>".encode('utf-8'), client_public_keys[nickname]))
                    else:
                        ban_user(args[1])

                elif command == "/msg":
                    if len(args) < 3:
                        client.send(rsa.encrypt("Usage: /msg <username> <message>".encode('utf-8'), client_public_keys[nickname]))
                    else:
                        target, private_message = args[1], " ".join(args[2:])
                        send_private_message(nickname, target, private_message)

                elif command == "/history":
                    cursor.execute("SELECT sender, message, timestamp FROM messages ORDER BY timestamp DESC LIMIT 5")
                    history = "\n".join([f"{row[2]} - {row[0]}: {row[1]}" for row in cursor.fetchall()])
                    client.send(rsa.encrypt(history.encode('utf-8'), client_public_keys[nickname]))

                else:
                    client.send(rsa.encrypt("Unknown command.".encode('utf-8'), client_public_keys[nickname]))
            else:
                broadcast(message, sender_nick=nickname)

        except:
            break

    client.close()
    del clients[nickname]
    del client_public_keys[nickname]
    broadcast(f"{nickname} left the chat.")

def receive_connections():
    while True:
        client, _ = server.accept()
        client.send("NICK".encode('utf-8'))
        nickname = client.recv(1024).decode('utf-8')

        if nickname in banned_users or nickname in clients:
            client.close()
            continue

        clients[nickname] = client
        client.send(SERVER_PUBLIC.save_pkcs1("PEM"))
        client_public_keys[nickname] = rsa.PublicKey.load_pkcs1(client.recv(2048))
        broadcast(f"{nickname} joined the chat.")
        thread = threading.Thread(target=handle_client, args=(client, nickname))
        thread.start()

receive_connections()
