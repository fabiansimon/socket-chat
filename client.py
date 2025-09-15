import socket
import threading

# .connect()
# .send()
# .recv()
# .close()

HOST = '127.0.0.1'
PORT = 12346


######################################################
# HELPER FUNCTIONS
######################################################

# share the encryption key with the server
def share_key(s, encr_key):
    s.sendall(f"PK {encr_key}".encode())

# receive the user id from the server
def receive_user_id(s):
    data = s.recv(1024).decode()
    display(data)

    user_id = data.find("[")
    user_id = data[user_id+1:data.find("]")]
    return user_id

# display the messages nicely
def display(data):
    print(f"\n> {data}")
    print("> ", end="", flush=True)

# encrypt the message using own key
def encrypt(key, message):
    key_bytes = key.encode()
    msg_bytes = message.encode()

    # simple XOR encryption
    cipher = bytes([m ^ key_bytes[i % len(key_bytes)] for i, m in enumerate(msg_bytes)])
    return cipher.hex()

# decrypt the cipher using own key
def decrypt(key, cipher):
    key_bytes = key.encode()
    cipher = bytes.fromhex(cipher)

    # simple XOR decryption
    plain = bytes([c ^ key_bytes[i % len(key_bytes)] for i, c in enumerate(cipher)])
    return plain.decode()

# share the chat id with the server
def share_chat_id(s, chat_id, key):
    ciper = encrypt(key, f"CID {chat_id}")
    s.sendall(ciper.encode())

# send the message to the server in the correct format
def send_message(s, encr_key, user_id, message):
    cipher = encrypt(encr_key, message)
    s.sendall(f"MSG {cipher}".encode())

# listen for messages from the server
def listen(s, key):
    while True:
        data = s.recv(2048)
        if not data:
            break

        # decode the data
        text = data.decode().strip()
        if text.startswith("MSG "):
            # decrypt the message
            cipher = text.split(maxsplit=1)[1]
            display(decrypt(key, cipher))

        # plain server messages
        else:
            display(text)



######################################################
# MAIN CLIENT
######################################################

# create a socket and connect to the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    user_id = None

    # share the encryption key
    encr_key = input("Please enter the encryption key you to use: ")
    share_key(s, encr_key)

    # share the chat id
    chat_id = input("Please enter the chat id you want to join: ")
    share_chat_id(s, chat_id, encr_key)
    user_id = receive_user_id(s)

    # listen for messages from the server concurrently
    threading.Thread(target=listen, args=(s,encr_key), daemon=True).start()

    while True:
        # send the message to the server
        message = input("> ")
        send_message(s, encr_key, user_id, message)