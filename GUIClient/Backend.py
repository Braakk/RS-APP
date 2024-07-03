import sqlite3
import socket
import time
from lib import RSAKey
import asyncio
import json
import ssl
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class Backend:
    def __init__(self, debug, hostname, port, disableSSL, allowInvalidCert):
        self.create_client_db()
        self.hostname = hostname
        self.ip = self.resolvIp(self.hostname)
        self.port = port
        self.reader = None
        self.writer = None
        self.connectionEstablished = asyncio.Event()
        self.rsaKey = RSAKey.RSAKey()
        self.rsaKey.load_key()
        self.debug = debug
        self.BUFFER = 4096
        self.disableSSL = disableSSL
        self.allowInvalidCert = allowInvalidCert
        self.username = None
        self.messageTopic = []
        self.messageReceived = asyncio.Event()
        self.syncDone = asyncio.Event()
        self.users = {}
        self.newUser = False
        self.current_conversation = "General"
        self.newMessage = False

    async def connectToServer(self):
        try:
            if not self.disableSSL:
                sslContext = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                if self.allowInvalidCert:
                    sslContext.check_hostname = False
                    sslContext.verify_mode = ssl.CERT_NONE
                self.reader, self.writer = await asyncio.open_connection(self.ip, self.port, ssl=sslContext)
            else:
                self.reader, self.writer = await asyncio.open_connection(self.ip, self.port)
            print("Connection established with the server.")
            self.connectionEstablished.set()
        except ConnectionResetError:
            print("The connection was terminated by the server. Make sure the server is up and SSL is enabled unless you have explicitly disabled the use of SSL.")
        except Exception as e:
            print(f"Error connecting to server: {e}")
            return None, None

    async def receiveMessage(self):
        try:
            message = await self.reader.read(self.BUFFER)
            if self.debug:
                print(f"Receiving: {message}")
            return json.loads(message)
        except ConnectionResetError:
            print("Connection lost. Trying to reconnect...")
            self.connectionEstablished.clear()
            if not await self.reconnect():
                exit(1)
        except Exception as e:
            print(f"Unexpected error: {e}")
            exit(1)
        
    async def sendMessage(self, message):
        try:
            if self.debug:
                print(f"Sending: {message}")
            self.writer.write(json.dumps(message).encode())
            await self.writer.drain()
        except ConnectionResetError:
            print("Connection lost. Trying to reconnect...")
            self.connectionEstablished.clear()
            if not await self.reconnect():
                exit(1)
        except Exception as e:
            print(f"Unexpected error: {e}")
            exit(1)

    async def sync(self):
        await self.sendMessage({"type": "sync", "lastSync": self.loadLastSync()})
        self.syncDone.clear()
        await self.syncDone.wait()
        self.loadUsers()

    # Traiter les messages utilisateur
    def processMessage(self, message):
        if message.get("sub-type") == "user":
            if message["To"] == self.username:
                # Decrypt the message
                encryptedMessage = bytes.fromhex(message["message"])
                decrypted = self.rsaKey.private_key.decrypt(
                    encryptedMessage,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                decryptedStr = decrypted.decode('utf-8')

                # Insert the message in the database
                self.insertOrUpdateReceivedMessageDB(message["messageId"], message["From"], message["To"], decryptedStr, message["message"], message["updatedAt"], message["createdAt"])
            else:
                self.UpdateUserMessageDB(message["messageId"], message["From"], message["To"], message["updatedAt"], message["createdAt"])
        self.updateLastSync(int(message["updatedAt"]))
        

    async def listenner(self):
        while True:
            message = await self.receiveMessage()
            if message:
                if message["type"] == "message":
                    self.processMessage(message)
                    if message["To"] == self.current_conversation or message["From"] == self.current_conversation:
                        self.newMessage = True
                
                elif message["type"] == "messageSync":
                    self.processMessage(message)
                    await self.sendMessage({"type": "syncReceived"})

                elif message["type"] == "user":
                    self.insertOrUpdateUser(message["email"], message["bio"], message["publicKey"], message["updatedAt"], message["createdAt"])
                    userEntry = {"profile": {"bio": message["bio"], "email": message["email"]}, "publicKey": message["publicKey"], "status": "Unknown"}
                    self.users[message["email"]] = userEntry
                    self.newUser = True
                    self.updateLastSync(int(message["updatedAt"]))
                
                elif message["type"] == "userSync":
                    self.insertOrUpdateUser(message["email"], message["bio"], message["publicKey"], message["updatedAt"], message["createdAt"])
                    self.updateLastSync(int(message["updatedAt"]))
                    await self.sendMessage({"type": "syncReceived"})

                elif message["type"] == "syncFinished":
                    self.syncDone.set()

                else:
                    # Ajout du message au sujet
                    self.messageTopic.append(message)
                    # Notification que le message a été reçu
                    self.messageReceived.set()
            else:
                print("Connection closed by the server.")
                await self.connectionEstablished.wait()

    async def sendUserMessage(self, to, message):
        # Récupérer la clé publique de l'utilisateur
        publicKeyPEM = self.users[to]["publicKey"]
        if publicKeyPEM is not None:
            # Load public key
            publicKey = serialization.load_pem_public_key(
                publicKeyPEM.encode(),
                backend=default_backend()
            )
        if not publicKey:
            print("The public key of the recipient is not available.")
            return

        # Chiffrer le message
        encrypted = publicKey.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        lastMessageId = self.getLatestMessageId(self.username, to) +1

        # Envoyer le message chiffré
        await self.sendMessage({"type": "message", "sub-type": "user", "messageId": lastMessageId, "email": to, "message": encrypted.hex()})
        self.insertMessageDB(lastMessageId, self.username, to, message, encrypted.hex(), None, None)

    def loadUserConversation(self, user):
        # Suivre ce pattern pour charger les messages de l'utilisateur
        # [02:20:40] pseudoExpéditeur: message
        sendMessage = self.getUserMessageDB(self.username, user)
        receiveMessage = self.getUserMessageDB(user, self.username)
        allMessages = sendMessage + receiveMessage
        allMessages.sort(key=lambda x: x[5])

        result = []
        for message in allMessages:
            if message[1] == self.username:
                msgStr = f"[{time.strftime('%H:%M:%S', time.localtime(message[5]))}] You: {message[3]}\n"
                result.append(msgStr)
            else:
                msgStr = f"[{time.strftime('%H:%M:%S', time.localtime(message[5]))}] {user}: {message[3]}\n"
                result.append(msgStr)
        return result

    @staticmethod
    def create_client_db():
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()

        c.execute('''CREATE TABLE IF NOT EXISTS UserMessage
                    (messageId INTEGER,
                    fromUserEmail TEXT,
                    toUserEmail TEXT,
                    message TEXT,
                    encryptedMessage TEXT,
                    createdAt INTEGER DEFAULT (strftime('%s', 'now')),
                    updatedAt INTEGER DEFAULT (strftime('%s', 'now')),
                    PRIMARY KEY (messageId, fromUserEmail, toUserEmail))''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS Personne
                    (personneId INTEGER PRIMARY KEY,
                    email TEXT UNIQUE,
                    bio TEXT,
                    publicKey TEXT,
                    createdAt INTEGER DEFAULT (strftime('%s', 'now')),
                    updatedAt INTEGER DEFAULT (strftime('%s', 'now')))''')

        conn.commit()
        conn.close()

    def loadUsers(self):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()

        c.execute("SELECT * FROM Personne")
        users = c.fetchall()
        conn.close()

        for user in users:
            userEntry = {"profile": {"bio": user[2], "email": user[1]}, "publicKey": user[3], "status": "Unknown"}
            self.users[user[1]] = userEntry

    @staticmethod
    def insertOrUpdateUser(email, bio, publicKey, updatedAt, createdAt):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()

        # Assurez-vous que la table Personne a un index UNIQUE ou PRIMARY KEY sur email
        c.execute("""
            INSERT INTO Personne (email, bio, publicKey) 
            VALUES (?, ?, ?) 
            ON CONFLICT(email) DO UPDATE SET 
            bio = excluded.bio, 
            publicKey = excluded.publicKey
        """, (email, bio, publicKey))

        conn.commit()
        conn.close()

    @staticmethod
    def getUserMessageDB(fromUserEmail, toUserEmail):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        query = '''SELECT * FROM UserMessage
                WHERE fromUserEmail = ? AND toUserEmail = ?'''
        c.execute(query, (fromUserEmail, toUserEmail))
        result = c.fetchall()
        conn.close()
        return result

    @staticmethod
    def insertMessageDB(messageId, fromUserEmail, toUserEmail, message, encryptedMessage, updatedAt, createdAt):
        timestamp = int(time.time())
        if updatedAt is None:
            updatedAt = timestamp
        if createdAt is None:
            createdAt = timestamp

        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()

        c.execute("""
        INSERT INTO UserMessage (messageId, fromUserEmail, toUserEmail, message, encryptedMessage)
        VALUES (?, ?, ?, ?, ?)
        """, (messageId, fromUserEmail, toUserEmail, message, encryptedMessage))
        conn.commit()
        conn.close()

    @staticmethod
    def insertOrUpdateReceivedMessageDB(messageId, fromUserEmail, toUserEmail, message, encryptedMessage, updatedAt, createdAt):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()

        # Vérifie si l'entrée existe déjà
        c.execute("""
        SELECT messageId FROM UserMessage WHERE messageId = ? AND fromUserEmail = ? AND toUserEmail = ?
        """, (messageId, fromUserEmail, toUserEmail))
        exists = c.fetchone()

        if exists:
            # Mise à jour de l'entrée existante
            c.execute("""
            UPDATE UserMessage
            SET message = ?, encryptedMessage = ?, updatedAt = ?, createdAt = ?
            WHERE messageId = ? AND fromUserEmail = ? AND toUserEmail = ?
            """, (message, encryptedMessage, updatedAt, createdAt, messageId, fromUserEmail, toUserEmail))
        else:
            # Insertion d'une nouvelle entrée
            c.execute("""
            INSERT INTO UserMessage (messageId, fromUserEmail, toUserEmail, message, encryptedMessage, updatedAt, createdAt)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (messageId, fromUserEmail, toUserEmail, message, encryptedMessage, updatedAt, createdAt))

        conn.commit()
        conn.close()

    @staticmethod
    def UpdateUserMessageDB(messageId, fromUserEmail, toUserEmail, updatedAt, createdAt):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()

        c.execute("""
        UPDATE UserMessage
        SET updatedAt = ?, createdAt = ?
        WHERE messageId = ? AND fromUserEmail = ? AND toUserEmail = ?
        """, (updatedAt, createdAt, messageId, fromUserEmail, toUserEmail))
        conn.commit()
        conn.close()

    @staticmethod
    def getLatestMessageId(fromUserEmail, toUserEmail):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()

        query = '''SELECT MAX(messageId) FROM UserMessage
                WHERE fromUserEmail = ? AND toUserEmail = ?'''
        
        c.execute(query, (fromUserEmail, toUserEmail))

        result = c.fetchone()
        
        conn.close()
        
        if result and result[0] is not None:
            return result[0]
        else:
            return -1

    @staticmethod
    def loadLastSync(filename='last_sync.txt'):
        try:
            with open(filename, 'a+') as file:
                file.seek(0)  # Retour au début du fichier pour lire le contenu
                content = file.read().strip()
                if not content:  # Si le fichier est vide, retourne None
                    return 0
                timestamp = int(content)
                return timestamp
        except ValueError:
            print("Le contenu du fichier n'est pas un nombre valide.")
            return None

    @staticmethod
    def updateLastSync(timestamp, filename='last_sync.txt'):
        # Only update the timestamp if it is greater than the current one
        if Backend.loadLastSync(filename) is None or timestamp > Backend.loadLastSync(filename):
            with open(filename, 'w') as file:
                file.write(str(timestamp))

    @staticmethod
    def resolvIp(address):
        try:
            serveurIpResolved = socket.gethostbyname(address)
        except socket.gaierror:
            print("Unable to resolve IP address or domain name.")
            return
        return serveurIpResolved