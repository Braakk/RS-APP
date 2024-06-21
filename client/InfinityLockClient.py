import asyncio
import socket
import argparse
import ssl
import json
from lib import RSAKey
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

reader, writer, connection_established, rsaKey = None, None, None, None
allowInvalidCert, sslDisabled = False, False
BUFFER = 4096

lock = asyncio.Lock()  # Créer un verrou pour éviter les problèmes de concurrence

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
    global reader, writer, connection_established
    reader, writer = None, None
    print("Attempting to reconnect...")
    for attempt in range(5):
        await asyncio.sleep(2 * attempt)  # Exponential backoff
        print(f"Reconnection attempt {attempt + 1}")
        await connectToServer(ip, port)
        if reader is not None and writer is not None:
            print("Reconnected successfully.")
            connection_established.set()
            return True
    print("Failed to reconnect after 5 attempts.")
    exit(1)

async def listen_for_messages(ip, port):
    global reader, connection_established, rsaKey
    while True:
        try:
            message = await reader.read(BUFFER)
            message = json.loads(message.decode())
            if message:
                # Decrypt the message
                encrypted_message = bytes.fromhex(message["message"])
                decrypted = rsaKey.private_key.decrypt(
                    encrypted_message,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                decrypted_str = decrypted.decode('utf-8')

                print("Message from " + message["From"] + ": " + decrypted_str)
            else:
                print("Connection closed by the server.")
                break
        except ConnectionResetError:
            print("Connection lost. Trying to reconnect...")
            connection_established.clear()
            if not await reconnect(ip, port):
                break  # Exit if unable to reconnect
        except Exception as e:
            print(f"Une erreur inattendue est survenue: {e}")
            break

async def send_messages():
    global writer, connection_established
    session = PromptSession()

    with patch_stdout():
        while True:
            try:
                emailUserToSend = await session.prompt_async("Email to send message to: ")
                message = await session.prompt_async("Your message: ")
                if message:
                    await connection_established.wait() # Wait for the connection to be established/reestablished
                    publicKeyPEM = await askPublicKey(emailUserToSend)
                    if emailUserToSend is None:
                        print("The user is not registered.")
                        continue
                    # Charger la clé publique
                    publicKey = serialization.load_pem_public_key(
                        publicKeyPEM.encode(),
                        backend=default_backend()
                    )

                    # Chiffrer le message
                    encrypted = publicKey.encrypt(
                        message.encode(),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )

                    # Format to Json
                    message = json.dumps({"type": "message", "email": emailUserToSend, "message": encrypted.hex()})

                    writer.write(message.encode())
                    await writer.drain()
            except KeyboardInterrupt:
                print("Connection closed by the user.")
                writer.close()
                await writer.wait_closed()
                exit(0)

async def login(email, rsaKey):
    global reader, writer
    print("RSA key loaded successfully.")
    writer.write(json.dumps({"type": "login", "authMethod": "RSASignature", "email": email}).encode())
    await writer.drain()
    received = await reader.read(BUFFER)
    message = json.loads(received.decode())
    print(f"Message from the server: {message}")
    if message["type"] != "login" or message["authMethod"] != "RSASignature" or message["Value"] is None:
        print("Unexpected message received. Exiting.")
        exit(1)

    # Sign the message with the RSA key and send it back to the server in hex format
    signature = rsaKey.sign(bytes.fromhex(message["Value"]))
    writer.write(json.dumps({"type": "login", "authMethod": "RSASignature", "signature": signature.hex()}).encode())
    await writer.drain()
    received = await reader.read(BUFFER)
    message = json.loads(received.decode())
    print(f"Message from the server: {message}")
    if message["type"] != "login" or message["status"] != "success":
        print("Unexpected message received. Exiting.")
        exit(1)
    print("Successfully logged in.")

async def register(email, rsaKey):
    global reader, writer
    try:
        writer.write(json.dumps({"type": "register", "email": email}).encode())
        await writer.drain()

        received = await reader.read(BUFFER)
        message = json.loads(received.decode())
        if message["type"] != "register" or message["message"] != "generateRSAKeys":
            print("Unexpected message received. Exiting.")
            exit(1)
        rsaKey.generate_keys()
        publicKey = rsaKey.get_public_key()
        writer.write(json.dumps({"type": "register", "publicKey": publicKey}).encode())
        await writer.drain()
        received = await reader.read(BUFFER)
        message = json.loads(received.decode())
        if message["type"] != "register" or message["status"] != "success":
            print("Unexpected message received. Exiting.")
            exit(1)
        print("Successfully registered.")
    except ConnectionResetError:
        print("The connection has been reset by the server. The server may have refused the message.")
        exit(1)
    except Exception as e:
        print(f"Error sending registration message: {e}")
        exit(1)

async def askPublicKey(email):
    global reader, writer
    writer.write(json.dumps({"type": "getPublicKey", "method": "email", "email": email}).encode())
    await writer.drain()
    received = await reader.read(BUFFER)
    message = json.loads(received.decode())
    if message["publicKey"] is None:
        print("Unexpected message received : ", message["message"])
        return None
    return message["publicKey"]

async def main(ip, port, args):
    global reader, writer, connection_established, rsaKey
    await connectToServer(ip, port)
    connection_established = asyncio.Event()
    connection_established.set()

    rsaKey = RSAKey.RSAKey()

    if reader is not None and writer is not None:
        if rsaKey.load_key() != False:
            await login(args.email, rsaKey)
        else:
            await register(args.email, rsaKey)
        await send_messages()
        # await asyncio.gather(
        #     listen_for_messages(ip, port),
        #     send_messages()
        # )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start the InfinityLock client.")
    parser.add_argument("-s", "--server", type=str, help="The address of the server", required=False, default="localhost")
    parser.add_argument("-p", "--port", type=int, help="The listening port of the server", required=False, default=5020)
    parser.add_argument("-e", "--email", type=str, help="The email address to use for registration", required=False, default="test")
    parser.add_argument("--disable-ssl", action="store_true", help="Disable SSL encryption", required=False, default=False)
    parser.add_argument("--allow-invalid-cert", action="store_true", help="Allow connections with invalid certificates", required=False, default=False)
    args = parser.parse_args()

    allowInvalidCert = args.allow_invalid_cert
    sslDisabled = args.disable_ssl


    asyncio.run(main(resolvIp(args.server), args.port, args))