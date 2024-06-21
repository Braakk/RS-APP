import threading
import json
import os
import pyotp
from lib.ClientManager import ClientManager
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

BUFFER = 4096

class ClientHandler(threading.Thread):
    def __init__(self, clientSocket, address, clientManager, debug=False):
        threading.Thread.__init__(self)
        self.clientSocket = clientSocket
        self.address = address
        self.clientManager: ClientManager = clientManager
        self.debug = debug
        self.email = None
        self.running = True
        self.start()  # Start the thread upon initialization

    def run(self):
        self.clientManager.add(self)
        self.handle_client()
    
    def sendMessage(self, message: dict):
        if self.debug:
            print(f"Sending to {self.address}: {message}")
        self.clientSocket.send(json.dumps(message).encode('utf-8'))

    def receiveMessage(self):
        message = self.clientSocket.recv(BUFFER).decode('utf-8')
        if self.debug:
            print(f"Receiving from {self.address}: {message}")
        return json.loads(message)

    def RSASignature(self, message):
        self.email = message["email"]
        if ClientManager.isClientRegistered(self.email) is None:
            self.sendMessage({"type": "error", "message": "The client is not registered"})
            self.clientSocket.close()
            self.clientManager.remove(self)
            print(f"Connection with {self.address} closed.")
            exit(1)
        else:
            random_value = os.urandom(32)
            self.sendMessage({"type": "login", "authMethod": "RSASignature", "Value" : random_value.hex()})
            message = self.receiveMessage()
            signature = bytes.fromhex(message["signature"])
            public_key = ClientManager.getPublicKey(self.email).encode('utf-8')
            public_key = serialization.load_pem_public_key(public_key, default_backend())
            try:
                public_key.verify(signature, random_value, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            except InvalidSignature:
                self.sendMessage({"type": "login", "authMethod": "RSASignature", "status": "failure"})
                self.clientSocket.close()
                self.clientManager.remove(self)
                print(f"Connection with {self.address} closed.")
                exit(1)
    
    def generateTOTPSecret(self):
        totp = pyotp.TOTP(pyotp.random_base32())
        print(totp.now())
        self.sendMessage({"type": "register", "message": "TOTPSecret", "secret": totp.secret})
        self.sendMessage({"type": "register", "message": "getTOTPToken"})
        message = self.receiveMessage()

        if message["type"] == "register" and message["authMethod"] == "TOTP" and message["Value"] is not None and totp.verify(message["Value"]):
            self.clientManager.insert2FA(self.email, totp.secret)
        else:
            self.sendMessage({"type": "login", "authMethod": "TOTP", "status": "failure"})
            self.clientSocket.close()
            self.clientManager.remove(self)
            print(f"Connection with {self.address} closed.")
            exit(1)

    def verifyTOTP(self, message, totpSecret):
        self.sendMessage({"type": "login", "authMethod": "TOTP", "message": "SendTOTPToken"})
        print("TOTP verification" + totpSecret.now())
        message = self.receiveMessage()
        if message["type"] == "login" and message["authMethod"] == "TOTP" and message["Value"] is not None and totpSecret.verify(message["Value"]):
            return
        else:
            self.sendMessage({"type": "login", "authMethod": "TOTP", "status": "failure"})
            self.clientSocket.close()
            self.clientManager.remove(self)
            print(f"Connection with {self.address} closed.")
            exit(1)

    def registering(self, message):
        self.email = message["email"]
        if ClientManager.isClientRegistered(self.email):
            self.sendMessage({"type": "error", "message": "The client is already registered"})
            self.clientSocket.close()
            self.clientManager.remove(self)
            print(f"Connection with {self.address} closed.")
            exit(1)
        else:
            self.sendMessage({"type": "register", "message": "generateRSAKeys"})
            message = self.receiveMessage()
            publicKey = message["publicKey"]
            ClientManager.insertClient(self.email, publicKey)
            self.sendMessage({"type": "register", "message": "add2FAMethod"})
            message = self.receiveMessage()
            if message["type"] == "register" and message["Value"] == "yes" and message["authMethod"] == "TOTP":
                self.generateTOTPSecret()

            self.sendMessage({"type": "register", "message": "Successfully registered", "status": "success"})

    def login(self):
        try:
            message = self.receiveMessage()
            if message["type"] == "login" and message["authMethod"] == "RSASignature":
                self.RSASignature(message)
                twoFA = ClientManager.get2FA(self.email)
                if twoFA is not None:
                    self.verifyTOTP(message, pyotp.TOTP(twoFA))
                self.sendMessage({"type": "login", "message": "Successfully logged in", "status": "success"})

            elif message["type"] == "register":
                self.registering(message)
            else:
                self.sendMessage({"type": "error", "message": "Unknown message type"})
                self.clientSocket.close()
                self.clientManager.remove(self)
                print(f"Connection with {self.address} closed.")
                exit(1)
        except Exception as e:
            print(f"Error while receiving login message: {e}")
            exit(1)

    def handle_client(self):
        try:
            self.login()
            while True:
                message = self.receiveMessage()
                print(f"Message from {self.address}: {message}")
                if not message:
                    break
                elif message["type"] == "getPublicKey":
                    public_key = self.clientManager.getPublicKey(message["email"])
                    if public_key is None:
                        self.sendMessage({"type": "error", "message": "The client is not registered"})
                    else:
                        self.sendMessage({"type": "getPublicKey", "publicKey": ClientManager.getPublicKey(message["email"])})
                elif message["type"] == "message":
                    self.clientManager.sendMessageToEmail(self, message["email"], message["message"])
                else:
                    self.sendMessage({"type": "error", "message": "Unknown message type"})
        except ConnectionAbortedError:
            print(f"Connection with {self.address} interrupted.")
        except json.JSONDecodeError as e:
            print(f"Error while decoding message: {e}")
        finally:
            self.clientSocket.close()
            self.clientManager.remove(self)
            print(f"Connection with {self.address} closed.")