import socket
import threading

# .connect()
# .send()
# .recv()
# .close()

HOST = '127.0.0.1'
PORT = 12346

def share_key(s, encr_key):
    s.sendall(f"PK {encr_key}".encode())

def receive_user_id(s):
    data = s.recv(1024).decode()
    display(data)

    user_id = data.find("[")
    user_id = data[user_id+1:data.find("]")]
    return user_id

def receive(s, encr_key = None):
    data = s.recv(1024).decode()
    message = data
    
    # If encryption key is provided, decrypt the message
    if (encr_key is not None):
        message = decrypt(encr_key, data)

    display(message)
    
def display(data):
    print(f"\n> {data}")
    print("> ", end="", flush=True)

def encrypt(key, message):
    key_bytes = key.encode()
    msg_bytes = message.encode()
    cipher = bytes([m ^ key_bytes[i % len(key_bytes)] for i, m in enumerate(msg_bytes)])
    return cipher.hex()

def decrypt(key, cipher):
    key_bytes = key.encode()
    cipher = bytes.fromhex(cipher)
    plain = bytes([c ^ key_bytes[i % len(key_bytes)] for i, c in enumerate(cipher)])
    return plain.decode()

def share_chat_id(s, chat_id, key):
    ciper = encrypt(key, f"CID {chat_id}")
    s.sendall(ciper.encode())

def send_message(s, encr_key, user_id, message):
    cipher = encrypt(encr_key, message)
    s.sendall(f"MSG {cipher}".encode())

def listen(s, key):
    while True:
        data = s.recv(2048)
        if not data:
            break
        text = data.decode().strip()
        if text.startswith("MSG "):
            cipher = text.split(maxsplit=1)[1]
            display(decrypt(key, cipher))

        else:
            display(text)   # plain server messages


######################################################

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    user_id = None

    # Share the encryption key
    encr_key = input("Please enter the encryption key you to use: ")
    share_key(s, encr_key)

    # Share the chat id
    chat_id = input("Please enter the chat id you want to join: ")
    share_chat_id(s, chat_id, encr_key)
    user_id = receive_user_id(s)

    threading.Thread(target=listen, args=(s,encr_key), daemon=True).start()

    while True:
        message = input("> ")
        send_message(s, encr_key, user_id, message)