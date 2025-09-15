import socket
import uuid
import traceback
import threading

# .bind()
# .listen()
# .accept()
# .connect()
# .connect_ex()
# .send()
# .recv()
# .close()

HOST = '127.0.0.1'
PORT = 12346

# Set to False to disable debug messages
DEBUG = True

CHATS = {}

######################################################
# HELPER FUNCTIONS
######################################################

# decrypt the cipher using the user key
def decrypt(key, cipher):
    key_bytes = key.encode()
    cipher = bytes.fromhex(cipher)

    # simple XOR decryption
    plain = bytes([c ^ key_bytes[i % len(key_bytes)] for i, c in enumerate(cipher)])
    return plain.decode()

# encrypt the message using the user key
def encrypt(key, message):
    key_bytes = key.encode()
    msg_bytes = message.encode()

    # simple XOR encryption
    cipher = bytes([m ^ key_bytes[i % len(key_bytes)] for i, m in enumerate(msg_bytes)])
    return cipher.hex()

# receive the key from the user
def receive_key(conn):
    key = None
    while key is None:
        data = conn.recv(1024).decode()
        key = extract_input(data, "PK")

        # if the key is not valid, send an error message
        if key is None:
            conn.sendall(b"Ensure you send a valid key, please try again with following format: PK <key>")

    return key

# receive the encrypted chat id from the user
def receive_chat_id(conn, key):
    chat_id = None
    while chat_id is None:
        data = conn.recv(1024).decode()
        debug(f"Received data: {data}")

        # decrypt the data using the user key
        data = decrypt(key, data)
        debug(f"Decrypted data: {data}")
        chat_id = extract_input(data, "CID")

        # if the chat id is not valid, send an error message
        if chat_id is None:
            conn.sendall(b"Ensure you send a valid chat id, please try again with following format: CID <chat_id>")

    return chat_id

# extract the input from the data using the keyword provided
def extract_input(data, keyword):
    try:
        # example data: CID 123456 -> CID = ChatID, 123456 = chat_id
        data = data.split()

        # if the data is not valid, return None
        if len(data) < 2:
            return None
        
        # if the keyword is found, return the input
        if data[0] == keyword:
            return data[1]

    except:
        print("Error extracting input")
        return None

# generate a unique user id
def gen_user_id():
    return str(uuid.uuid4())

# extract the excluded users from the message (if provided)
def excluded_users(message):
    start = message.find("[")
    end = message.find("]")

    # none excluded
    if start == -1 or end == -1:
        return []
    
    # return the excluded users
    return message[start+1:end].split(",")

# extract the message from the data using the key and user id
def extract_message(data, key, user_id):
    data = data.split()
    cipher = data[1:][0]
    message = decrypt(key, cipher)
    excluded = excluded_users(message)

    # If no excluded users, return the message and an empty list
    if len(excluded) == 0:

        # still exclude the author so they don't receive their own message
        return message, [user_id]

    # If there are excluded users, return the message and the excluded users
    message = message[:message.find("[")-1]

    # Add the user id to the excluded users and make it unique
    # this is to ensure the author doesn't receive their own message
    excluded.append(user_id)
    excluded = list(set(excluded))

    return message, excluded
    
# receive and the message from our client script
def receive(conn, chat_id, user_id):
    data = conn.recv(1024).decode()
    key = CHATS[chat_id][user_id]["key"]
    message, excluded = extract_message(data, key, user_id)

    # generate the message to be displayed
    return f"[{chat_id}] [{user_id}]: {message}", excluded

# broadcast the message to all users from same chat
def broadcast(message, chat_id, excluded_users):
    exclude = set(excluded_users)
    for user_id, info in CHATS[chat_id].items():
        key = info["key"]
        conn = info["conn"]

        # skip if the user is in the excluded users
        if user_id in exclude: continue

        # encrypt the message according to the user key
        cipher = encrypt(key, message)
        debug(f"Sending message to {user_id}: {cipher}")
        conn.sendall(f"MSG {cipher}".encode())

# simple debug function
def debug(output): 
    if DEBUG: 
        print(f"[DEBUG] {output}")

######################################################
# HANDLE INDIVIDUAL CLIENTS
######################################################

def handle_client(conn, addr):
    try: 
        debug(f"Connected by {addr}")

        ### Initial setup for the chat

        # Receive the encryption key
        encr_key = receive_key(conn)
        debug(f"Encryption key received: {encr_key}")
        conn.sendall(b"Key exchanged successfully, please now send the chat id in following format: CID <chat_id>")

        # Receive the chat id
        chat_id = receive_chat_id(conn, encr_key)
        debug(f"Chat id received: {chat_id}")
        user_id = gen_user_id()
        conn.sendall(f"Chat id received successfully, Your user id is [{user_id}]\n".encode())
        debug(f"User id generated: {user_id}")

        # Create chat if it doesn't exist
        if CHATS.get(chat_id) is None:
            CHATS[chat_id] = {}

        # Store the encryption key and user id in CHATS 
        CHATS[chat_id][user_id] = { "key": encr_key, "conn": conn }
        online_users = CHATS[chat_id]

        conn.sendall(f"You successfully joined the chat, online users are {online_users.keys()}\n".encode())
        conn.sendall(f"Send your message in following format: <message> [user,ids,to,exclude (optional, separate with comma)]".encode())

        # listen for messages from the client and broadcast them to all other users of the same chat
        while True:
            msg, excluded = receive(conn, chat_id, user_id)
            broadcast(msg, chat_id, excluded)

    except Exception as e:
        debug(f"Error in connection: {e}")
        traceback.print_exc()
        conn.close()
        
    # finally close the connection and delete the user from the chat
    finally: 
        conn.close()
        del CHATS[chat_id][user_id]
        
######################################################
# MAIN SERVER
######################################################

print("Waiting for a connection...")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    ## Allow reuse of the port
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()

    # listen for connections from clients and handle them in a new thread
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()