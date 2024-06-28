import asyncio
import socket
import argparse
import ssl
import json
import sqlite3
import time
from lib import RSAKey
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

reader, writer, connectionEstablished, rsaKey = None, None, None, None

messageTopic = []
condition = asyncio.Condition()
args = None
debug = False

BUFFER = 4096

def create_client_db():
    conn = sqlite3.connect('client_data.db')
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS UserMessage
                 (messageId INTEGER,
                  fromUserEmail TEXT,
                  toUserEmail TEXT,
                  message TEXT,
                  encryptedMessage TEXT,
                  timestamp INTEGER,
                  PRIMARY KEY (messageId, fromUserEmail, toUserEmail))''')

    conn.commit()
    conn.close()

def insertOrUpdateMessageDB(messageId, fromUserEmail, toUserEmail, message, encryptedMessage, timestamp):
    conn = sqlite3.connect('client_data.db')
    c = conn.cursor()

    c.execute("""
    INSERT INTO UserMessage (messageId, fromUserEmail, toUserEmail, message, encryptedMessage, timestamp)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(messageId, fromUserEmail, toUserEmail) DO UPDATE SET
    message = excluded.message,
    encryptedMessage = excluded.encryptedMessage,
    timestamp = excluded.timestamp
    """, (messageId, fromUserEmail, toUserEmail, message, encryptedMessage, timestamp))
    conn.commit()
    conn.close()

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

def loadLastSync(filename='last_sync.txt'):
    try:
        with open(filename, 'r') as file:
            timestamp = int(file.read().strip())
            return timestamp
    except FileNotFoundError:
        print(f"Le fichier {filename} n'a pas été trouvé.")
        return None
    except ValueError:
        print("Le contenu du fichier n'est pas un nombre valide.")
        return None

def updateLastSync(timestamp, filename='last_sync.txt'):
    with open(filename, 'w') as file:
        file.write(str(timestamp))

async def sendMessage(message: dict):
    global debug, writer
    try:
        if debug:
            print(f"Sending: {message}")
        writer.write(json.dumps(message).encode())
        await writer.drain()
    except ConnectionResetError:
        print("The connection has been reset by the server. The server may have refused the message.")
        writer.close()
        exit(1)
    except json.JSONDecodeError as e:
        print(f"Error while decoding message: {e}")
        writer.close()
        exit(1)
    except Exception as e:
        print(f"Error sending message: {e}")
        writer.close()
        exit(1)

async def receiveMessage():
    global debug, reader
    try:
        message = await reader.read(BUFFER)
        if debug:
            print(f"Receiving: {message}")
        return json.loads(message)
    except ConnectionResetError:
        print("Connection lost. Trying to reconnect...")
        connectionEstablished.clear()
        if not await reconnect():
            exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        exit(1)

def resolvIp(address):
    try:
        serveurIpResolved = socket.gethostbyname(address)
    except socket.gaierror:
        print("Unable to resolve IP address or domain name.")
        return
    return serveurIpResolved

async def connectToServer():
    global reader, writer, args
    try:
        if not args.disable_ssl:
            sslContext = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            if args.allow_invalid_cert:
                sslContext.check_hostname = False
                sslContext.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.open_connection(args.server, args.port, ssl=sslContext)
        else:
            reader, writer = await asyncio.open_connection(args.server, args.port)
        print("Connection established with the server.")
    except ConnectionResetError:
        print("The connection was terminated by the server. Make sure the server is up and SSL is enabled unless you have explicitly disabled the use of SSL.")
    except Exception as e:
        print(f"Error connecting to server: {e}")
        return None, None
    
async def reconnect():
    global reader, writer, connectionEstablished, args, rsaKey
    reader, writer = None, None
    print("Attempting to reconnect...")
    for attempt in range(5):
        await asyncio.sleep(2 * attempt)  # Exponential backoff
        print(f"Reconnection attempt {attempt + 1}")
        await connectToServer()
        if reader is not None and writer is not None:
            print("Reconnected successfully.")
            await login(args.email, rsaKey)
            connectionEstablished.set()
            return True
    print("Failed to reconnect after 5 attempts.")
    exit(1)

async def listenner():
    global reader, connectionEstablished, rsaKey, condition, messageTopic, args
    while True:
        message = await receiveMessage()
        if message:
            if message["type"] == "message":
                # Decrypt the message
                encryptedMessage = bytes.fromhex(message["message"])
                decrypted = rsaKey.private_key.decrypt(
                    encryptedMessage,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                decryptedStr = decrypted.decode('utf-8')

                # Insert the message in the database
                insertOrUpdateMessageDB(message["messageId"], message["From"], message["To"], decryptedStr, message["message"], message["timestamp"])
                print(f"Message from {message['From']}: {decryptedStr}")
            else:
                async with condition:
                    messageTopic.append(message)
                    condition.notify_all()
        else:
            print("Connection closed by the server.")
            await connectionEstablished.wait()

async def sendMessages(email):
    global writer, connectionEstablished, condition, messageTopic
    session = PromptSession()

    with patch_stdout():
        while True:
            try:
                emailUserToSend = await session.prompt_async("Email to send message to: ")
                message = await session.prompt_async("Your message: ")
                if message:
                    await connectionEstablished.wait() # Wait for the connection to be established/reestablished
                    publicKeyPEM = await askPublicKey(emailUserToSend)
                    if publicKeyPEM is not None:
                        # Load public key
                        publicKey = serialization.load_pem_public_key(
                            publicKeyPEM.encode(),
                            backend=default_backend()
                        )

                        # Encrypt the message
                        encrypted = publicKey.encrypt(
                            message.encode(),
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )

                        # Format to Json
                        messageId = getLatestMessageId(email, emailUserToSend) +1
                        timestamp = int(time.time())

                        insertOrUpdateMessageDB(messageId, email, emailUserToSend, message, encrypted.hex(), timestamp)

                        message = {"type": "message", "email": emailUserToSend, "message": encrypted.hex(), "timestamp": timestamp, "messageId": messageId}
                        await sendMessage(message)
            except KeyboardInterrupt:
                print("Connection closed by the user.")
                writer.close()
                await writer.wait_closed()
                exit(0)

async def login(email, rsaKey):
    global reader, writer
    login = False
    print("RSA key loaded successfully.")
    await sendMessage({"type": "login", "authMethod": "RSASignature", "email": email})

    while not login:
        message = await receiveMessage()

        if message.get("type") == "login" and message.get("authMethod") == "RSASignature" and message.get("Value") is not None:
            # Sign the message with the RSA key and send it back to the server in hex format
            signature = rsaKey.sign(bytes.fromhex(message["Value"]))
            await sendMessage({"type": "login", "authMethod": "RSASignature", "signature": signature.hex()})

        elif message.get("type") == "login" and message.get("authMethod") == "TOTP" and message.get("message") == "SendTOTPToken":
            totpToken = input("Enter the TOTP token: ")
            await sendMessage({"type": "login", "authMethod": "TOTP", "Value": totpToken})

        elif message.get("type") == "login" and message.get("status") == "success":
            login = True
            await sendMessage({"type": "syncMessage", "beginTimestamp": loadLastSync()})

        else:
            print("Unexpected message received. Exiting.")
            writer.close()
            exit(1)
    print("Successfully logged in.")


async def register(email, rsaKey):
    global reader, writer
    await sendMessage({"type": "register", "email": email})

    login = False
    while not login:
        message = await receiveMessage()

        if message["type"] == "register" and message["message"] == "generateRSAKeys":
            rsaKey.generate_keys()
            publicKey = rsaKey.get_public_key()
            await sendMessage({"type": "register", "publicKey": publicKey})
        
        elif message["type"] == "register" and message["message"] == "add2FAMethod":
            add2FA = input("Do you want to add a 2FA method? (y/n): ")
            add2FA = "yes" if add2FA.lower() == "y" or add2FA.lower() == "yes" else "no"
            await sendMessage({"type": "register", "Value": add2FA, "authMethod": "TOTP"})

        elif message["type"] == "register" and message["message"] == "TOTPSecret":
            print("TOTP secret: ", message["secret"])

        elif message["type"] == "register" and message["message"] == "getTOTPToken":
            totpToken = input("Enter the TOTP token: ")
            await sendMessage({"type": "register", "authMethod": "TOTP", "Value": totpToken})

        elif message["type"] == "register" and message["status"] == "success":
            login = True
            updateLastSync(int(time.time()))
            print("Successfully registered.")

        else:
            print("Unexpected message received. Exiting.")
            writer.close()
            exit(1)

async def askPublicKey(email):
    global writer, condition, messageTopic
    await sendMessage({"type": "getPublicKey", "method": "email", "email": email})
    async with condition:
        await condition.wait()
        message = messageTopic.pop()
        if message.get("type") == "error":
            print(f"Error message received {message['errorCode']}: {message['message']}")
        elif message.get("publicKey") is None:
            print("Unexpected message received : ", message["message"])
            return None
        return message["publicKey"]

async def main():
    global reader, writer, connectionEstablished, rsaKey
    await connectToServer()
    connectionEstablished = asyncio.Event()
    connectionEstablished.set()

    rsaKey = RSAKey.RSAKey()

    if reader is not None and writer is not None:
        if rsaKey.load_key() != False:
            await login(args.email, rsaKey)
        else:
            await register(args.email, rsaKey)
        await asyncio.gather(
            listenner(),
            sendMessages(args.email)
        )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start the InfinityLock client.")
    parser.add_argument("-s", "--server", type=str, help="The address of the server", required=False, default="localhost")
    parser.add_argument("-p", "--port", type=int, help="The listening port of the server", required=False, default=5020)
    parser.add_argument("-e", "--email", type=str, help="The email address to use for registration", required=True)
    parser.add_argument("--disable-ssl", action="store_true", help="Disable SSL encryption", required=False, default=False)
    parser.add_argument("--allow-invalid-cert", action="store_true", help="Allow connections with invalid certificates", required=False, default=False)
    parser.add_argument("--debug", action="store_true", help="Enable debug mode", required=False, default=False)
    args = parser.parse_args()

    debug = args.debug

    create_client_db()

    args.server = resolvIp(args.server)
    asyncio.run(main())