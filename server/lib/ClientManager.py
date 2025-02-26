import sqlite3
import time
import logging

class ClientManager:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(ClientManager, cls).__new__(cls)
        return cls._instance

    def __init__(self, debug=False):
        if not hasattr(self, 'initialized'):
            self.clients = []
            self.debug = debug
            self.initialized = True

    def add(self, clientHandler):
        self.clients.append(clientHandler)

    def remove(self, clientHandler):
        self.clients.remove(clientHandler)

    def sendToAll(self, message):
        for client in self.clients:
            client.sendMessage(message)

    def sendToAllExcept(self, message, clientHandler):
        for client in self.clients:
            if client != clientHandler:
                client.sendMessage(message)

    def sendToAllNewUser(self, clientHandler, personneId):
        user = self.getUser(personneId)
        self.sendToAllExcept({"type": "user", "email": user[1], "bio": user[2], "publicKey": user[3], "updatedAt": user[5], "createdAt": user[4]}, clientHandler)

    def sendMessageByEmail(self, clientHandler, email, message, messageId):
        personneId = self.getPersonneIdFromEmail(email)
        if personneId is None:
            clientHandler.sendMessage({"type": "error", "errorCode": 1, "message": "The client is not registered"})
            return
        messageInfo = self.addMessageToDB(clientHandler.personneId, personneId, message, messageId)
        if "error" in messageInfo:
            clientHandler.sendMessage({"type": "error", "errorCode": 3, "message": messageInfo["error"]})
            return
        for client in self.clients:
            if client.personneId == personneId:
                client.sendMessage({"type": "message", "sub-type": "user", "messageId": messageInfo["messageId"], "From": clientHandler.email, "To": email, "message": message, "createdAt": messageInfo["createdAt"], "updatedAt": messageInfo["updatedAt"]})
        clientHandler.sendMessage({"type": "message", "sub-type": "user", "messageId": messageInfo["messageId"], "From": clientHandler.email, "To": email, "message": message, "createdAt": messageInfo["createdAt"], "updatedAt": messageInfo["updatedAt"]})

    def sendMessageToGroup(self, clientHandler, groupId, message, messageId):
        if groupId is None:
            clientHandler.sendMessage({"type": "error", "errorCode": 2, "message": "The group does not exist"})
            return
        messageInfo = self.addMessageToGroupDB(groupId, message)
        UsersId = self.getUsersIdInGroup(groupId)
        for client in self.clients:
            if client.personneId in UsersId:
                client.sendMessage({"type": "message", "messageId": messageId, "From": clientHandler.email, "groupId": groupId, "message": message, "timestamp": messageInfo["timestamp"]})

    def getAllSince(self, clientHandler, lastUpdate):
        self.getAllMessageSince(clientHandler, lastUpdate)
        self.getAllUsersSince(clientHandler, lastUpdate)
        clientHandler.sendMessage({"type": "syncFinished"})

    def getAllMessageSince(self, clientHandler, lastUpdate):
        messages = ClientManager.getUserMessagesFromDBSince(clientHandler.personneId, lastUpdate)
        for message in messages:
            clientHandler.sendMessage({"type": "messageSync", "sub-type": "user", "messageId": message[0],"From": ClientManager.getEmailFromPersonneId(message[1]), "To": ClientManager.getEmailFromPersonneId(message[2]), "message": message[3], "updatedAt": message[5], "createdAt": message[4]})
            message = clientHandler.receiveMessage()
            if message["type"] != "syncReceived":
                self.clientSocket.close()
                self.remove(clientHandler)
                msg = f"Connection with {self.address} closed."
                print(msg)
                logging.error(msg)
                exit(1)

    def getAllUsersSince(self, clientHandler, lastUpdate):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        c.execute("SELECT * FROM Personne WHERE updatedAt > ?", (lastUpdate,))
        result = c.fetchall()
        conn.close()
        for user in result:
            clientHandler.sendMessage({"type": "userSync", "email": user[1], "bio": user[2], "publicKey": user[3], "updatedAt": user[5], "createdAt": user[4]})
            message = clientHandler.receiveMessage()
            if message["type"] != "syncReceived":
                self.clientSocket.close()
                self.remove(clientHandler)
                msg = f"Connection with {self.address} closed."
                print(msg)
                logging.error(msg)
                exit(1)

    @staticmethod
    def getUser(personneId):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        c.execute("SELECT * FROM Personne WHERE personneId = ?", (personneId,))
        result = c.fetchone()
        conn.close()
        return result

    @staticmethod
    def insertClient(email, bio, public_key):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        c.execute("INSERT INTO Personne (email, bio, publicKey) VALUES (?, ?, ?)", (email, bio, public_key))
        conn.commit()
        conn.close()

    @staticmethod
    def getPersonneIdFromEmail(email):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        c.execute("SELECT personneId FROM Personne WHERE email = ?", (email,))
        result = c.fetchone()
        conn.close()
        if result:
            return result[0]
        else:
            return None
        
    @staticmethod
    def getEmailFromPersonneId(personneId):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        c.execute("SELECT email FROM Personne WHERE personneId = ?", (personneId,))
        result = c.fetchone()
        conn.close()
        if result:
            return result[0]
        else:
            return None
    
    @staticmethod
    def isClientRegistered(email):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        c.execute("SELECT * FROM Personne WHERE email = ?", (email,))
        result = c.fetchone()
        conn.close()
        return result is not None
    
    @staticmethod
    def updateProfile(personneId, email, bio):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        c.execute("UPDATE Personne SET email = ?, bio = ?, updatedAt = CURRENT_TIMESTAMP WHERE personneId = ?", (email, bio, personneId))
        conn.commit()
        conn.close()
    
    @staticmethod
    def getPublicKey(email):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        c.execute("SELECT publicKey FROM Personne WHERE email = ?", (email,))
        result = c.fetchone()
        conn.close()
        if result:
            return result[0]
        else:
            return None
    
    @staticmethod
    def get2FA(personneId):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        c.execute("SELECT secret_2fa FROM Client2FA WHERE personneId = ?", (personneId,))
        result = c.fetchone()
        conn.close()
        if result:
            return result[0]
        else:
            return None
    
    @staticmethod
    def insert2FA(personneId, secret_2fa):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        c.execute("INSERT INTO Client2FA (personneId, secret_2fa) VALUES (?, ?)", (personneId, secret_2fa))
        conn.commit()
        conn.close()

    @staticmethod
    def getLatestMessageId(fromUserId, toUserId):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()

        query = '''SELECT MAX(messageId) FROM UserMessage
                WHERE fromUserId = ? AND toUserId = ?'''
        
        c.execute(query, (fromUserId, toUserId))

        result = c.fetchone()
        
        conn.close()
        
        if result and result[0] is not None:
            return result[0]
        else:
            return -1

    @staticmethod
    def addMessageToDB(fromUserId, toUserId, message, messageId):
        if messageId != ClientManager.getLatestMessageId(fromUserId, toUserId) + 1:
            return {"error": "An error occured while adding the message to the database. Resyncronize the client."}
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        c.execute("INSERT INTO UserMessage (messageId, fromUserId, toUserId, message) VALUES (?, ?, ?, ?)", (messageId, fromUserId, toUserId, message))
        conn.commit()

        # Récupérer createdAt et updatedAt pour la ligne insérée
        c.execute("SELECT createdAt, updatedAt FROM UserMessage WHERE messageId = ?", (messageId,))
        row = c.fetchone()
        conn.close()
        if row:
            return {"messageId": messageId, "createdAt": row[0], "updatedAt": row[1]}
        else:
            return {"error": "Failed to retrieve createdAt and updatedAt."}

    @staticmethod
    def getMessagesFromDB(personneId):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        c.execute("SELECT * FROM UserMessage WHERE toUserId = ?", (personneId,))
        result = c.fetchall()
        conn.close()
        return result
    
    @staticmethod
    def getUserMessagesFromDBSince(personneId, beginTimestamp):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        c.execute("SELECT * FROM UserMessage WHERE toUserId = ? AND updatedAt > ?", (personneId, beginTimestamp))
        result = c.fetchall()
        conn.close()
        return result
    
    @staticmethod
    def createGroup(groupeName, synchroneKeyEncryption, personneId):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        c.execute("INSERT INTO Groupe (groupName, synchroneKeyEncryption) VALUES (?, ?)", (groupeName, synchroneKeyEncryption))
        groupeId = c.lastrowid
        c.execute("INSERT INTO PersonneGroupe (personneId, groupeId, authorizationId) VALUES (?, ?, ?)", (personneId, groupeId, 1))
        conn.commit()
        conn.close()
        return groupeId
    
    @staticmethod
    def addMessageToGroupDB(groupeId, message):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        timestamp = int(time.time())
        c.execute("INSERT INTO GroupeMessage (groupeId, message, timestamp) VALUES (?, ?, ?)", (groupeId, message, timestamp))
        conn.commit()
        conn.close()
        message_id = c.lastrowid
        return {"messageId": message_id, "timestamp": timestamp}
    
    @staticmethod
    def getUsersIdInGroup(groupeId):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        c.execute("SELECT personneId FROM PersonneGroupe WHERE groupeId = ?", (groupeId,))
        result = c.fetchall()
        conn.close()
        return result