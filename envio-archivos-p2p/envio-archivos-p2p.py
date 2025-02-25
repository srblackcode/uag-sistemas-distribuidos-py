import socket
import os

# Configuración del servidor (Nodo receptor)
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5002
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(1)
    print(f"[*] Esperando conexión en {SERVER_HOST}:{SERVER_PORT}...")
    
    client_socket, address = server_socket.accept()
    print(f"[+] Conectado con {address}")
    
    # Asegurar recepción completa de la cabecera
    received = b""
    while not received.endswith(SEPARATOR.encode()):
        received += client_socket.recv(BUFFER_SIZE)
    
    received = received.decode().strip(SEPARATOR)
    try:
        filename, filesize = received.split(SEPARATOR)
        filename = os.path.basename(filename)
        filesize = int(filesize)
    except ValueError:
        print("[!] Error al procesar la cabecera. Datos recibidos:", received)
        client_socket.close()
        server_socket.close()
        return
    
    with open(f"received_{filename}", "wb") as file:
        bytes_received = 0
        while bytes_received < filesize:
            bytes_read = client_socket.recv(BUFFER_SIZE)
            if not bytes_read:
                break
            file.write(bytes_read)
            bytes_received += len(bytes_read)
            print(f"Recibido: {bytes_received}/{filesize} bytes")
    
    print(f"[+] Archivo {filename} recibido correctamente.")
    client_socket.close()
    server_socket.close()


# Configuración del cliente (Nodo emisor)
CLIENT_HOST = "127.0.0.1"
CLIENT_PORT = 5002

def send_file(filename):
    filesize = os.path.getsize(filename)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((CLIENT_HOST, CLIENT_PORT))
    
    client_socket.sendall(f"{filename}{SEPARATOR}{filesize}{SEPARATOR}".encode())
    
    with open(filename, "rb") as file:
        while (bytes_read := file.read(BUFFER_SIZE)):
            client_socket.sendall(bytes_read)
    
    print(f"[+] Archivo {filename} enviado correctamente.")
    client_socket.close()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "server":
        start_server()
    elif len(sys.argv) > 2 and sys.argv[1] == "client":
        send_file(sys.argv[2])
    else:
        print("Uso:")
        print("Para iniciar el servidor: python script.py server")
        print("Para enviar un archivo: python script.py client <archivo>")
