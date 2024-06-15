import argparse
import asyncio
import socket
import signal
import sys
from types import FrameType

# To print properly received message without interfering with the user's input
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

def sigint_handler(signum: int, frame: FrameType):
    exit(0)

# Declare the signal handled by the program
signal.signal(signal.SIGINT, sigint_handler)

# Define the arguments of the python executable (-h is automatically generated)
parser = argparse.ArgumentParser(description="Start the server InfinityLock.")
#parser.add_argument("-u", "--user", type=str, help="The user to use", required=True)
#parser.add_argument("-P", "--password", type=str, help="The password of the user", required=True)
parser.add_argument("-s", "--server", type=str, help="The address of the server", required=False, default="localhost")
parser.add_argument("-p", "--port", type=int, help="The listening port of the server", required=False, default=5020)

# To retrieve the launch arguments
# Argument analysis
args = parser.parse_args()

async def listen_for_messages(sock):
    while True:
        message = await asyncio.get_event_loop().sock_recv(sock, 1024)
        if message:
            print(f"Message from the server: {message.decode()}")
            print("Your message: ", end='', flush=True)
        else:
            print("Connection closed by the server.")
            sock.close()
            break

async def send_messages(sock):
    # Create a prompt session
    session = PromptSession()
    while True:
        with patch_stdout():
            message = await session.prompt_async("Your message: ")
        if message:
            await asyncio.get_event_loop().sock_sendall(sock, message.encode())

async def main():
    # Résolve/verify the address of the server
    try:
        # Obtient l'adresse IP associée au nom de domaine (si serveurIp est un nom de domaine)
        # ou valide l'adresse IP (si serveurIp est déjà une adresse IP)
        serveurIpResolved = socket.gethostbyname(args.server)
    except socket.gaierror:
        print("Impossible de résoudre l'adresse IP ou le nom de domaine.")
        return


    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    await asyncio.get_event_loop().sock_connect(sock, (serveurIpResolved, args.port))
    print("Connexion établie avec le serveur.")

    listen_task = asyncio.create_task(listen_for_messages(sock))
    send_task = asyncio.create_task(send_messages(sock))

    await asyncio.gather(listen_task, send_task)

if __name__ == "__main__":
    asyncio.run(main())