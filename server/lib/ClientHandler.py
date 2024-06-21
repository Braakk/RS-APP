import threading
import json
import os
from lib.ClientManager import ClientManager
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

BUFFER = 4096

class ClientHandler(threading.Thread):
    def __init__(self, clientSocket, address, clientManager):
        threading.Thread.__init__(self)
        self.clientSocket = clientSocket
        self.address = address
        self.clientManager: ClientManager = clientManager
        self.email = None
        self.running = True
        self.start()  # Start the thread upon initialization

    def run(self):
        self.clientManager.add(self)
        self.handle_client()

    def RSASignature(self, message):
        self.email = message["email"]
        if ClientManager.isClientRegistered(self.email) is None:
            self.clientSocket.send(json.dumps({"type": "error", "message": "The client is not registered"}).encode('utf-8'))
            self.clientSocket.close()
            self.clientManager.remove(self)
            print(f"Connection with {self.address} closed.")
            exit(1)
        else:
            random_value = os.urandom(32)
            self.clientSocket.send(json.dumps({"type": "login", "authMethod": "RSASignature", "Value" : random_value.hex()}).encode('utf-8'))
            message = self.clientSocket.recv(BUFFER).decode('utf-8')
            if message is None:
                print(f"Error while receiving signature from {self.address}")
                exit(1)
            message = json.loads(message)
            signature = bytes.fromhex(message["signature"])
            public_key = ClientManager.getPublicKey(self.email).encode('utf-8')
            public_key = serialization.load_pem_public_key(public_key, default_backend())
            try:
                public_key.verify(signature, random_value, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                self.clientSocket.send(json.dumps({"type": "login", "authMethod": "RSASignature", "status": "success"}).encode('utf-8'))
            except InvalidSignature:
                self.clientSocket.send(json.dumps({"type": "login", "authMethod": "RSASignature", "status": "failure"}).encode('utf-8'))
                self.clientSocket.close()
                self.clientManager.remove(self)
                print(f"Connection with {self.address} closed.")
                exit(1)

    def registering(self, message):
        self.email = message["email"]
        if ClientManager.isClientRegistered(self.email):
            self.clientSocket.send(json.dumps({"type": "error", "message": "The client is already registered"}).encode('utf-8'))
            self.clientSocket.close()
            self.clientManager.remove(self)
            print(f"Connection with {self.address} closed.")
            exit(1)
        else:
            self.clientSocket.send(json.dumps({"type": "register", "message": "generateRSAKeys"}).encode('utf-8'))
            message = self.clientSocket.recv(BUFFER).decode('utf-8')
            if message is None:
                print(f"Error while receiving public key from {self.address}")
                exit(1)
            message = json.loads(message)
            publicKey = message["publicKey"]
            ClientManager.insertClient(self.email, publicKey)
            self.clientSocket.send(json.dumps({"type": "register", "status": "success"}).encode('utf-8'))

    def login(self):
        try:
            message = self.clientSocket.recv(BUFFER).decode('utf-8')
            message = json.loads(message)
            if message["type"] == "login" and message["authMethod"] == "RSASignature":
                self.RSASignature(message)
            elif message["type"] == "register":
                self.registering(message)
        except Exception as e:
            print(f"Error while receiving login message: {e}")
            exit(1)

    def handle_client(self):
        try:
            self.login()
            while True:
                message = self.clientSocket.recv(BUFFER).decode('utf-8')
                message = json.loads(message)
                print(f"Message from {self.address}: {message}")
                if not message:
                    break
                elif message["type"] == "getPublicKey":
                    public_key = self.clientManager.getPublicKey(message["email"])
                    if public_key is None:
                        self.clientSocket.send(json.dumps({"type": "error", "message": "The client is not registered"}).encode('utf-8'))
                    else:
                        self.clientSocket.send(json.dumps({"type": "getPublicKey", "publicKey": ClientManager.getPublicKey(message["email"])}).encode('utf-8'))
                elif message["type"] == "message":
                    self.clientManager.sendMessageToEmail(self, message["email"], message["message"])
                else:
                    self.clientSocket.send(json.dumps({"type": "error", "message": "Unknown message type"}).encode('utf-8'))
        except ConnectionAbortedError:
            print(f"Connection with {self.address} interrupted.")
        finally:
            self.clientSocket.close()
            self.clientManager.remove(self)
            print(f"Connection with {self.address} closed.")