import sqlite3
import json

class ClientManager:
    def __init__(self):
        self.clients = []

    def add(self, clientHandler):
        self.clients.append(clientHandler)

    def remove(self, clientHandler):
        self.clients.remove(clientHandler)

    def sendMessageToEmail(self, clientHandler, email, message):
        for client in self.clients:
            if client.email == email:
                # Send the message to the client in json format
                client.clientSocket.send(json.dumps({"type": "message", "From": clientHandler.email, "To": email, "message": message}).encode('utf-8'))

    @staticmethod
    def insertClient(email, public_key):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        c.execute("INSERT INTO clients (email, public_key) VALUES (?, ?)", (email, public_key))
        conn.commit()
        conn.close()

    @staticmethod
    def isClientRegistered(email):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        c.execute("SELECT * FROM clients WHERE email = ?", (email,))
        result = c.fetchone()
        conn.close()
        return result is not None

    @staticmethod
    def getPublicKey(email):
        conn = sqlite3.connect('client_data.db')
        c = conn.cursor()
        c.execute("SELECT public_key FROM clients WHERE email = ?", (email,))
        result = c.fetchone()
        conn.close()
        if result:
            return result[0]
        else:
            return None