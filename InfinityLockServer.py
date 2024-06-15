import argparse
import socket
import threading
import signal
from types import FrameType

def sigint_handler(signum: int, frame: FrameType):
    if len(clients) != 0:
        print("Closing clients connections...")
    for client in clients:
        client.close()
    print("Closing the server...")
    server_socket.close()
    print("Server closed succesfully.")
    exit(0)

# Declare the signal handled by the program
signal.signal(signal.SIGINT, sigint_handler)

# Define the arguments of the python executable (-h is automatically generated)
parser = argparse.ArgumentParser(description="Start the server InfinityLock.")
parser.add_argument("-p", "--port", type=int, help="The listening port of the server", required=False, default=5020)
parser.add_argument("-a", "--address", type=str, help="The listening address of the server", required=False, default='0.0.0.0')

# To retrieve the launch arguments
# Argument analysis
args = parser.parse_args()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((args.address, args.port))
server_socket.listen()
server_socket.settimeout(0.3)
print("Listening on port " + str(args.address) + ":" + str(args.port))

clients = []

def handle_client(client, address, clients):
    try:
        while True:
            message = client.recv(1024).decode('utf-8')
            if not message:
                break
            print(f"Message from {address}: {message}")
            # Renvoyer le message à tous les autres clients
            for other_client in clients:
                if other_client is not client:  # Ne pas renvoyer au même client
                    try:
                        other_client.send(message.encode('utf-8'))
                    except Exception as e:
                        print(f"Erreur lors de l'envoi du message: {e}")
    finally:
        client.close()
        clients.remove(client)
        print(f"Connection with {address} closed.")

while True:
    try:
        client, address = server_socket.accept()
        print(f"Connection from {address} accepted.")
        clients.append(client)  # Ajouter le nouveau client à la liste
        # Créer un nouveau thread pour gérer la communication avec ce client
        thread = threading.Thread(target=handle_client, args=(client, address, clients))
        thread.start()
    except socket.timeout:
        continue
    except KeyboardInterrupt:
        break