import socket
import threading
import json
import os
import logging
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
        self.clientSocket: socket = clientSocket
        self.address = address
        self.clientManager: ClientManager = clientManager
        self.debug: bool = debug
        self.personneId: int = None
        self.email: str = None
        self.running: bool = True
        self.start()  # Start the thread upon initialization

    def run(self):
        self.clientManager.add(self)
        self.handle_client()
    
    def sendMessage(self, message: dict):
        log_message = f"Sending to {self.address}, {self.personneId}, {self.email}: {message}"
        logging.info(log_message)
        if self.debug:
            print(log_message)
        self.clientSocket.send(json.dumps(message).encode('utf-8'))

    def receiveMessage(self):
        message = self.clientSocket.recv(BUFFER).decode('utf-8')
        log_message = f"Receiving from {self.address}, {self.personneId}, {self.email}: {message}"
        logging.info(log_message)
        if self.debug:
            print(log_message)
        return json.loads(message)

    def RSASignature(self, message):
        self.email = message["email"]
        if not ClientManager.isClientRegistered(self.email):
            self.sendMessage({"type": "error", "message": "The client is not registered"})
            self.clientSocket.close()
            self.clientManager.remove(self)
            msg = f"Connection with {self.address} closed."
            print(msg)
            logging.error(msg)
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
                msg = f"Connection with {self.address} closed."
                print(msg)
                logging.error(msg)
                exit(1)
    
    def generateTOTPSecret(self):
        totp = pyotp.TOTP(pyotp.random_base32())
        self.sendMessage({"type": "register", "message": "TOTPSecretAndGetTOTPToken", "secret": totp.secret})
        message = self.receiveMessage()

        if message["type"] == "register" and message["authMethod"] == "TOTP" and message["Value"] is not None and totp.verify(message["Value"]):
            pass
        else:
            self.sendMessage({"type": "register", "authMethod": "TOTP", "status": "failure"})
            self.clientSocket.close()
            self.clientManager.remove(self)
            msg = f"Connection with {self.address} closed."
            print(msg)
            logging.error(msg)
            exit(1)
        return totp

    def verifyTOTP(self, message, totpSecret):
        self.sendMessage({"type": "login", "authMethod": "TOTP", "message": "SendTOTPToken"})
        message = self.receiveMessage()
        if message["type"] == "login" and message["authMethod"] == "TOTP" and message["Value"] is not None and totpSecret.verify(message["Value"]):
            return
        else:
            self.sendMessage({"type": "login", "authMethod": "TOTP", "status": "failure"})
            self.clientSocket.close()
            self.clientManager.remove(self)
            msg = f"Connection with {self.address} closed."
            print(msg)
            logging.error(msg)
            exit(1)

    def registering(self, message: dict):
        self.email = message["email"]
        bio = message["bio"]
        if ClientManager.isClientRegistered(self.email):
            self.sendMessage({"type": "error", "message": "The client is already registered"})
            self.clientSocket.close()
            self.clientManager.remove(self)
            msg = f"Connection with {self.address} closed."
            print(msg)
            logging.error(msg)
            exit(1)
        else:
            self.sendMessage({"type": "register", "message": "generateRSAKeys"})
            message = self.receiveMessage()
            publicKey = message["publicKey"]
            self.sendMessage({"type": "register", "message": "add2FAMethod"})
            message = self.receiveMessage()

            totp = None
            if message["type"] == "register" and message["Value"] == "yes" and message["authMethod"] == "TOTP":
                totp = self.generateTOTPSecret()

            ClientManager.insertClient(self.email, bio, publicKey)
            self.personneId = ClientManager.getPersonneIdFromEmail(self.email)
            if totp is not None:
                self.clientManager.insert2FA(self.personneId, totp.secret)

            self.clientManager.sendToAllNewUser(self, self.personneId)
            self.sendMessage({"type": "register", "message": "Successfully registered", "status": "success"})

    def login(self):
        try:
            message = self.receiveMessage()
            if message["type"] == "login" and message["authMethod"] == "RSASignature":
                self.email = message["email"]
                if not ClientManager.isClientRegistered(self.email):
                    self.sendMessage({"type": "error", "message": "The client is not registered"})
                    self.clientSocket.close()
                    self.clientManager.remove(self)
                    msg = f"Connection with {self.address} closed."
                    print(msg)
                    logging.error(msg)
                    exit(1)
                self.personneId = ClientManager.getPersonneIdFromEmail(self.email)
                self.RSASignature(message)
                twoFA = ClientManager.get2FA(self.personneId)
                if twoFA is not None:
                    self.verifyTOTP(message, pyotp.TOTP(twoFA))
                self.sendMessage({"type": "login", "message": "Successfully logged in", "status": "success"})

            elif message["type"] == "register":
                self.registering(message)
            else:
                self.sendMessage({"type": "error", "message": "Unknown message type"})
                self.clientSocket.close()
                self.clientManager.remove(self)
                msg = f"Connection with {self.address} closed."
                print(msg)
                logging.error(msg)
                exit(1)
        except Exception as e:
            msg = f"Error while receiving login message: {e}"
            print(msg)
            logging.error(msg)
            exit(1)

    def handle_client(self):
        try:
            self.login()
            while True:
                message = self.receiveMessage()
                if not message:
                    break
                elif message["type"] == "getPublicKey":
                    public_key = self.clientManager.getPublicKey(message["email"])
                    if public_key is None:
                        self.sendMessage({"type": "error", "message": "The client is not registered"})
                    else:
                        self.sendMessage({"type": "getPublicKey", "publicKey": ClientManager.getPublicKey(message["email"])})
                elif message["type"] == "message":
                    if message["sub-type"] == "user":
                        self.clientManager.sendMessageByEmail(self, message["email"], message["message"], message["messageId"])
                    elif message["sub-type"] == "group":
                        self.clientManager.sendMessageToGroup(self, message["groupId"], message["message"])
                elif message["type"] == "sync":
                    self.clientManager.getAllSince(self, message.get("lastSync", 0))
                # elif message["type"] == "syncMessage":
                #     self.clientManager.getAllMessageSince(self, message.get("lastSync", 0))
                # elif message["type"] == "getAllUsers":
                #     self.clientManager.getAllUsersSince(self, message.get("lastSync", 0))
                elif message["type"] == "updateProfile":
                    self.clientManager.updateProfile(self.personneId, message["bio"], message["publicKey"])
                    self.sendMessage({"type": "updateProfile", "message": "Successfully updated profile", "status": "success"})
                elif message["type"] == "create":
                    self.clientManager.createGroup(message["groupName"], message["key"], self.personneId)
                else:
                    self.sendMessage({"type": "error", "message": "Unknown message type"})
        except ConnectionAbortedError:
            msg = f"Connection with {self.address} interrupted."
            print(msg)
            logging.error(msg)
        except json.JSONDecodeError as e:
            msg = f"Error while decoding message: {e}"
            print(msg)
            logging.error(msg)
        finally:
            self.clientSocket.close()
            self.clientManager.remove(self)
            msg = f"Connection with {self.address} closed."
            print(msg)
            logging.info(msg)