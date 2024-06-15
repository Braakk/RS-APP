import asyncio
import socket
import argparse
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

reader, writer, connection_established = None, None, None

def resolvIp(address):
    try:
        serveurIpResolved = socket.gethostbyname(address)
    except socket.gaierror:
        print("Unable to resolve IP address or domain name.")
        return
    return serveurIpResolved

async def connectToServer(ip, port):
    global reader, writer
    try:
        reader, writer = await asyncio.open_connection(ip, port)
        print("Connection established with the server.")
    except Exception as e:
        print(f"Error connecting to server: {e}")
        return None, None
    
async def reconnect(server, port):
    global reader, writer, connection_established
    reader, writer = None, None
    print("Attempting to reconnect...")
    for attempt in range(5):
        await asyncio.sleep(2 * attempt)  # Exponential backoff
        print(f"Reconnection attempt {attempt + 1}")
        await connectToServer(server, port)
        if reader is not None and writer is not None:
            print("Reconnected successfully.")
            connection_established.set()
            return True
    print("Failed to reconnect after 5 attempts.")
    exit(1)

async def listen_for_messages(ip, port):
    global reader, connection_established
    while True:
        try:
            message = await reader.read(1024)
            if message:
                print(f"Message from the server: {message.decode()}")
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
            message = await session.prompt_async("Your message: ")
            if message:
                await connection_established.wait() # Wait for the connection to be established/reestablished
                writer.write(message.encode())
                await writer.drain()

async def main(ip, port):
    global reader, writer, connection_established
    await connectToServer(ip, port)
    connection_established = asyncio.Event()
    connection_established.set()

    if reader is not None and writer is not None:
        await asyncio.gather(
            listen_for_messages(ip, port),
            send_messages()
        )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start the InfinityLock client.")
    parser.add_argument("-s", "--server", type=str, help="The address of the server", required=False, default="localhost")
    parser.add_argument("-p", "--port", type=int, help="The listening port of the server", required=False, default=5020)
    args = parser.parse_args()

    asyncio.run(main(resolvIp(args.server), args.port))