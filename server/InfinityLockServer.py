import argparse
import socket
import ssl
import threading
import signal
import sqlite3
import json
import os
from lib import ssl_certificate_utils
from types import FrameType
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

clients = []
serverSocket = None

generateDefaultCert = False

BUFFER = 4096

def sigint_handler(signum: int, frame: FrameType):
    global clients, serverSocket

    if len(clients) != 0:
        print("Closing clients connections...")
    for client in clients:
        client.close()
    
    print("Closing the server...")
    serverSocket.close()
    print("Server closed succesfully.")
    exit(0)

def create_db():
    conn = sqlite3.connect('client_data.db')
    c = conn.cursor()
    # Crée la table si elle n'existe pas déjà
    c.execute('''CREATE TABLE IF NOT EXISTS clients
                 (email TEXT PRIMARY KEY, public_key TEXT)''')
    conn.commit()
    conn.close()

def insert_client(email, public_key):
    conn = sqlite3.connect('client_data.db')
    c = conn.cursor()
    c.execute("INSERT INTO clients (email, public_key) VALUES (?, ?)", (email, public_key))
    conn.commit()
    conn.close()

def is_client_registered(email):
    conn = sqlite3.connect('client_data.db')
    c = conn.cursor()
    c.execute("SELECT * FROM clients WHERE email = ?", (email,))
    result = c.fetchone()
    conn.close()
    return result is not None

def get_public_key(email):
    conn = sqlite3.connect('client_data.db')
    c = conn.cursor()
    c.execute("SELECT public_key FROM clients WHERE email = ?", (email,))
    result = c.fetchone()
    conn.close()
    if result:
        return result[0]
    else:
        return None
    
def RSASignature(client, address, message, clients):
    # Check if the client is registered
    email = message["email"]
    if is_client_registered(email) is None:
        client.send(json.dumps({"type": "error", "message": "The client is not registered"}).encode('utf-8'))
        client.close()
        clients.remove(client)
        print(f"Connection with {address} closed.")
        exit(1)
    else:
        random_value = os.urandom(32)
        # Send the random value to the client for signature
        client.send(json.dumps({"type": "login", "authMethod": "RSASignature", "Value" : random_value.hex()}).encode('utf-8'))
        print({"type": "login", "authMethod": "RSASignature", "Value" : random_value.hex()})
        message = client.recv(BUFFER).decode('utf-8')
        if message is None:
            print(f"Error while receiving signature from {address}")
            exit(1)
        message = json.loads(message)
        print(f"Message from {address}: {message}")
        # Check the signature
        if message["type"] == "login" and message["authMethod"] == "RSASignature" and message["signature"] is not None:
            signature = bytes.fromhex(message["signature"])
            public_key = get_public_key(email).encode('utf-8')
            public_key = serialization.load_pem_public_key(public_key, default_backend())
            try:
                # If the signature is valid, the client is authenticated
                public_key.verify(signature, random_value, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                client.send(json.dumps({"type": "login", "authMethod": "RSASignature", "status": "success"}).encode('utf-8'))
            except InvalidSignature:
                # If the signature is invalid, the client is disconnected
                client.send(json.dumps({"type": "login", "authMethod": "RSASignature", "status": "failure"}).encode('utf-8'))
                client.close()
                clients.remove(client)
                print(f"Connection with {address} closed.")
                exit(1)

def registering(client, address, message, clients):
    email = message["email"]
    if is_client_registered(message["email"]):
        client.send(json.dumps({"type": "error", "message": "The client is already registered"}).encode('utf-8'))
        client.close()
        clients.remove(client)
        print(f"Connection with {address} closed.")
        exit(1)
    else:
        client.send(json.dumps({"type": "register", "message": "generateRSAKeys"}).encode('utf-8'))
        message = client.recv(BUFFER).decode('utf-8')
        if message is None:
            print(f"Error while receiving public key from {address}")
            exit(1)
        message = json.loads(message)
        print(f"Message from {address}: {message}")
        if message["type"] == "register" and message["publicKey"] is not None:
            public_key = message["publicKey"]
            insert_client(email, public_key)
            client.send(json.dumps({"type": "register", "status": "success"}).encode('utf-8'))
    
def login(client, address, clients):
    try:
        message = client.recv(BUFFER).decode('utf-8')
        message = json.loads(message)
        print(f"Message from {address}: {message}")
        # If the client wants to login with RSA signature (already registered)
        if message["type"] == "login" and message["authMethod"] == "RSASignature":
            RSASignature(client, address, message, clients)
        # If the client is not registered
        elif message["type"] == "register":
            registering(client, address, message, clients)
    except Exception as e:
        print(f"Error while receiving login message: {e}")
        exit(1)

def handle_client(client, address, clients):
    try:
        login(client, address, clients)
        while True:
            message = client.recv(BUFFER).decode('utf-8')
            if not message:
                break
            print(f"Message from {address}: {message}")
            # Send message to all other clients
            for other_client in clients:
                if other_client is not client:  # Do not resend to the same client
                    try:
                        other_client.send(message.encode('utf-8'))
                    except Exception as e:
                        print(f"Erreur lors de l'envoi du message: {e}")
    except ConnectionAbortedError:
        print(f"Connection with {address} interrupted.")
    finally:
        client.close()
        clients.remove(client)
        print(f"Connection with {address} closed.")

def main(args):
    global clients, serverSocket

    # Create the database
    create_db()

    # Create the server socket
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.bind((args.address, args.port))
    serverSocket.listen()
    serverSocket.settimeout(0.3)
    print("Listening on port " + str(args.address) + ":" + str(args.port))

    # Create the SSL context
    if not args.disable_ssl:
        sslContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        if (args.cert_path is not None and args.key_path is not None) or args.generate_default_cert:
            if args.generate_default_cert:
                args.cert_path = (args.cert_path, "certs/server.crt")[args.cert_path is None]
                args.key_path = (args.key_path, "certs/server.key")[args.key_path is None]
                
                ssl_certificate_utils.generate_ssl_certificates(args.cert_path, args.key_path)
            sslContext.load_cert_chain(certfile=args.cert_path, keyfile=args.key_path)
        else:
            print("You must specify the path to the SSL certificate and key files or disable SSL encryption with --disable-ssl or enable the generation of self-signed cert.")
            exit(1)

        # Wrap server socket in SSL context
        serverSocket = sslContext.wrap_socket(serverSocket, server_side=True)

    # Handle the clients
    while True:
        try:
            client, address = serverSocket.accept()
            print(f"Connection from {address} accepted.")
            clients.append(client)  # Add the new client to the list
            # Create a new thread to handle the communication with this client
            thread = threading.Thread(target=handle_client, args=(client, address, clients))
            thread.start()
        except socket.timeout:
            continue

        # Handle SSL errors
        except ssl.SSLEOFError as e:
            print(f"Erreur SSL: {e}")
            continue
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    # Declare the signal handled by the program
    signal.signal(signal.SIGINT, sigint_handler)

    # Define the arguments of the python executable (-h is automatically generated)
    parser = argparse.ArgumentParser(description="Start the server InfinityLock.")
    parser.add_argument("-p", "--port", type=int, help="The listening port of the server", required=False, default=5020)
    parser.add_argument("-a", "--address", type=str, help="The listening address of the server", required=False, default='0.0.0.0')
    parser.add_argument("--disable-ssl", action="store_true", help="Disable SSL encryption", required=False, default=False)
    parser.add_argument("--cert-path", type=str, help="Path to the SSL certificate file", required=False)
    parser.add_argument("--key-path", type=str, help="Path to the SSL private key file", required=False)
    parser.add_argument("--generate-default-cert", action="store_true", help="Generates SSL certificates by default if they are not already present (default path: certificate=certs/server.crt, private key=certs/server.key). Use path arguments to override these default locations.", required=False, default=False)
    args = parser.parse_args()

    main(args)