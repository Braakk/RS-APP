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
allowInvalidCert, sslDisabled = False, False

messageTopic = []
condition = asyncio.Condition()

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

def insertMessageDB(messageId, fromUserEmail, toUserEmail, message, encryptedMessage, timestamp):
    conn = sqlite3.connect('client_data.db')
    c = conn.cursor()

    c.execute("INSERT INTO UserMessage (messageId, fromUserEmail, toUserEmail, message, encryptedMessage, timestamp) VALUES (?, ?, ?, ?, ?, ?)", (messageId, fromUserEmail, toUserEmail, message, encryptedMessage, timestamp))
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


def resolvIp(address):
    try:
        serveurIpResolved = socket.gethostbyname(address)
    except socket.gaierror:
        print("Unable to resolve IP address or domain name.")
        return
    return serveurIpResolved

async def connectToServer(ip, port):
    global reader, writer, allowInvalidCert
    try:
        if not sslDisabled:
            sslContext = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            if allowInvalidCert:
                sslContext.check_hostname = False
                sslContext.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.open_connection(ip, port, ssl=sslContext)
        else:
            reader, writer = await asyncio.open_connection(ip, port)
        print("Connection established with the server.")
    except ConnectionResetError:
        print("The connection was terminated by the server. Make sure the server is up and SSL is enabled unless you have explicitly disabled the use of SSL.")
    except Exception as e:
        print(f"Error connecting to server: {e}")
        return None, None
    
async def reconnect(ip, port):
    global reader, writer, connectionEstablished
    reader, writer = None, None
    print("Attempting to reconnect...")
    for attempt in range(5):
        await asyncio.sleep(2 * attempt)  # Exponential backoff
        print(f"Reconnection attempt {attempt + 1}")
        await connectToServer(ip, port)
        if reader is not None and writer is not None:
            print("Reconnected successfully.")
            connectionEstablished.set()
            return True
    print("Failed to reconnect after 5 attempts.")
    exit(1)

async def listenner(ip, port):
    global reader, connectionEstablished, rsaKey, condition, messageTopic
    while True:
        try:
            message = await reader.read(BUFFER)
            message = json.loads(message.decode())
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
                    insertMessageDB(message["messageId"], message["From"], message["To"], decryptedStr, message["message"], message["timestamp"])

                    print("Message from " + message["From"] + ": " + decryptedStr)
                else:
                    print("Message received: ", message)
                    async with condition:
                        messageTopic.append(message)
                        condition.notify_all()
            else:
                print("Connection closed by the server.")
                break
        except ConnectionResetError:
            print("Connection lost. Trying to reconnect...")
            connectionEstablished.clear()
            if not await reconnect(ip, port):
                break  # Exit if unable to reconnect
        except Exception as e:
            print(f"Une erreur inattendue est survenue: {e}")
            break

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
                    if emailUserToSend is None:
                        print("The user is not registered.")
                        continue
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
                    message = json.dumps({"type": "message", "email": emailUserToSend, "message": encrypted.hex(), "timestamp": timestamp, "messageId": messageId})

                    insertMessageDB(messageId, email, emailUserToSend, message, encrypted.hex(), timestamp)

                    writer.write(message.encode())
                    await writer.drain()
            except KeyboardInterrupt:
                print("Connection closed by the user.")
                writer.close()
                await writer.wait_closed()
                exit(0)

async def login(email, rsaKey):
    global reader, writer
    login = False
    print("RSA key loaded successfully.")
    try:
        writer.write(json.dumps({"type": "login", "authMethod": "RSASignature", "email": email}).encode())
        await writer.drain()

        while not login:
            received = await reader.read(BUFFER)
            message = json.loads(received.decode())
            print(f"Message from the server: {message}")

            if message.get("type") == "login" and message.get("authMethod") == "RSASignature" and message.get("Value") is not None:
                # Sign the message with the RSA key and send it back to the server in hex format
                signature = rsaKey.sign(bytes.fromhex(message["Value"]))
                writer.write(json.dumps({"type": "login", "authMethod": "RSASignature", "signature": signature.hex()}).encode())
                await writer.drain()

            elif message.get("type") == "login" and message.get("authMethod") == "TOTP" and message.get("message") == "SendTOTPToken":
                totpToken = input("Enter the TOTP token: ")
                writer.write(json.dumps({"type": "login", "authMethod": "TOTP", "Value": totpToken}).encode())
                await writer.drain()

            elif message.get("type") == "login" and message.get("status") == "success":
                login = True
                writer.write(json.dumps({"type": "syncMessage", "beginTimestamp": loadLastSync()}).encode())

            else:
                print("Unexpected message received. Exiting.")
                writer.close()
                exit(1)
        print("Successfully logged in.")
    except ConnectionResetError:
        print("The connection has been reset by the server. The server may have refused the message.")
        writer.close()
        exit(1)
    except json.JSONDecodeError as e:
        print(f"Error while decoding message: {e}")
        writer.close()
        exit(1)
    except Exception as e:
        print(f"Error sending registration message: {e}")
        exit(1)


async def register(email, rsaKey):
    global reader, writer
    try:
        writer.write(json.dumps({"type": "register", "email": email}).encode())
        await writer.drain()

        login = False
        while not login:
            received = await reader.read(BUFFER)
            message = json.loads(received.decode())

            if message["type"] == "register" and message["message"] == "generateRSAKeys":
                rsaKey.generate_keys()
                publicKey = rsaKey.get_public_key()
                writer.write(json.dumps({"type": "register", "publicKey": publicKey}).encode())
                await writer.drain()
            
            elif message["type"] == "register" and message["message"] == "add2FAMethod":
                add2FA = input("Do you want to add a 2FA method? (y/n): ")
                add2FA = "yes" if add2FA.lower() == "y" or add2FA.lower() == "yes" else "no"
                writer.write(json.dumps({"type": "register", "Value": add2FA, "authMethod": "TOTP"}).encode())
                await writer.drain()

            elif message["type"] == "register" and message["message"] == "TOTPSecret":
                print("TOTP secret: ", message["secret"])

            elif message["type"] == "register" and message["message"] == "getTOTPToken":
                totpToken = input("Enter the TOTP token: ")
                writer.write(json.dumps({"type": "register", "authMethod": "TOTP", "Value": totpToken}).encode())
                await writer.drain()

            elif message["type"] == "register" and message["status"] == "success":
                login = True
                updateLastSync(int(time.time()))
                print("Successfully registered.")

            else:
                print("Unexpected message received. Exiting.")
                writer.close()
                exit(1)

    except ConnectionResetError:
        print("The connection has been reset by the server. The server may have refused the message.")
        writer.close()
        exit(1)
    except json.JSONDecodeError as e:
        print(f"Error while decoding message: {e}")
        writer.close()
        exit(1)
    except Exception as e:
        print(f"Error sending registration message: {e}")
        exit(1)

async def askPublicKey(email):
    global writer, condition, messageTopic
    writer.write(json.dumps({"type": "getPublicKey", "method": "email", "email": email}).encode())
    await writer.drain()
    async with condition:
        await condition.wait()
        message = messageTopic.pop()
        if message["publicKey"] is None:
            print("Unexpected message received : ", message["message"])
            return None
        return message["publicKey"]

async def main(ip, port, args):
    global reader, writer, connectionEstablished, rsaKey
    await connectToServer(ip, port)
    connectionEstablished = asyncio.Event()
    connectionEstablished.set()

    rsaKey = RSAKey.RSAKey()

    if reader is not None and writer is not None:
        if rsaKey.load_key() != False:
            await login(args.email, rsaKey)
        else:
            await register(args.email, rsaKey)
        await asyncio.gather(
            listenner(ip, port),
            sendMessages(args.email)
        )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start the InfinityLock client.")
    parser.add_argument("-s", "--server", type=str, help="The address of the server", required=False, default="localhost")
    parser.add_argument("-p", "--port", type=int, help="The listening port of the server", required=False, default=5020)
    parser.add_argument("-e", "--email", type=str, help="The email address to use for registration", required=True)
    parser.add_argument("--disable-ssl", action="store_true", help="Disable SSL encryption", required=False, default=False)
    parser.add_argument("--allow-invalid-cert", action="store_true", help="Allow connections with invalid certificates", required=False, default=False)
    args = parser.parse_args()

    allowInvalidCert = args.allow_invalid_cert
    sslDisabled = args.disable_ssl

    create_client_db()

    asyncio.run(main(resolvIp(args.server), args.port, args))