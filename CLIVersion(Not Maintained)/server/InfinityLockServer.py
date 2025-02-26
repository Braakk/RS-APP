import argparse
import socket
import ssl
import signal
import sqlite3
from lib import ClientHandler
from lib import ClientManager
from lib import ssl_certificate_utils
from types import FrameType

clients = []
serverSocket = None

generateDefaultCert = False

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

    # Creating the Person table
    c.execute('''CREATE TABLE IF NOT EXISTS Personne
                 (personneId INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT UNIQUE,
                  publicKey TEXT)''')

    # Creating the UserMessage table
    c.execute('''CREATE TABLE IF NOT EXISTS UserMessage
                 (messageId INTEGER,
                  fromUserId INTEGER,
                  toUserId INTEGER,
                  message TEXT,
                  timestamp INTEGER,
                  FOREIGN KEY(fromUserId) REFERENCES Personne(personneId),
                  FOREIGN KEY(toUserId) REFERENCES Personne(personneId),
                  PRIMARY KEY (messageId, fromUserId, toUserId))''')

    # Creating the Group table
    c.execute('''CREATE TABLE IF NOT EXISTS Groupe
                 (groupeId INTEGER PRIMARY KEY AUTOINCREMENT,
                  groupName TEXT,
                  synchroneKeyEncryption TEXT)''')

    # Creating the GroupeMessage table
    c.execute('''CREATE TABLE IF NOT EXISTS GroupeMessage
                 (groupeMessageId INTEGER PRIMARY KEY AUTOINCREMENT,
                  groupeId INTEGER,
                  message TEXT,
                  timestamp INTEGER,
                  FOREIGN KEY(groupeId) REFERENCES Groupe(groupeId))''')

    # Creating the AuthorizationType table
    c.execute('''CREATE TABLE IF NOT EXISTS AuthorizationType
                 (authorizationId INTEGER PRIMARY KEY AUTOINCREMENT,
                  description TEXT)''')

    # Creating the PersonneGroupe table
    c.execute('''CREATE TABLE IF NOT EXISTS PersonneGroupe
                 (personneId INTEGER,
                  groupeId INTEGER,
                  authorizationId INTEGER,
                  FOREIGN KEY(personneId) REFERENCES Personne(personneId),
                  FOREIGN KEY(groupeId) REFERENCES Groupe(groupeId),
                  FOREIGN KEY(authorizationId) REFERENCES AuthorizationType(authorizationId),
                  PRIMARY KEY(personneId, groupeId))''')

    # Creating the Client2FA table
    c.execute('''CREATE TABLE IF NOT EXISTS Client2FA
                 (personneId INTEGER PRIMARY KEY,
                  secret_2fa TEXT,
                  FOREIGN KEY(personneId) REFERENCES Personne(personneId))''')

    conn.commit()
    conn.close()

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

    clientManager = ClientManager.ClientManager(args.debug)

    # Handle the clients
    while True:
        try:
            client, address = serverSocket.accept()
            print(f"Connection from {address} accepted.")
            clients.append(client)  # Add the new client to the list
            # Create a new thread to handle the communication with this client
            ClientHandler.ClientHandler(client, address, clientManager, args.debug)
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
    parser.add_argument('--debug', action='store_true', help="Activate debug mode to display the exchanged messages", required=False, default=False)
    args = parser.parse_args()

    main(args)