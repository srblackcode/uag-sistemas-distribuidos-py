import socket
import threading
import pickle
from cryptography.fernet import Fernet

# Parámetros de conexión y cifrado
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 12345
ENCRYPTION_KEY = b'R1dJWWdUbXp1cVdpWlZoNUR5eEx4c3BYdExQeU5yYm0='
cipher_suite = Fernet(ENCRYPTION_KEY)

# Diccionarios para clientes y sus grupos
clients = {}       # {username: client_socket}
client_groups = {} # {username: group}
clients_lock = threading.Lock()

def recvall(sock, n):
    """Recibe exactamente n bytes del socket."""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def send_packet(sock, message):
    """
    Envía un mensaje prefijándolo con 4 bytes que indican su longitud.
    """
    msg_length = len(message)
    sock.sendall(msg_length.to_bytes(4, byteorder='big') + message)

def broadcast(message, group, exclude_socket=None):
    """Envía el mensaje a todos los clientes conectados en el mismo grupo, salvo el que se desee excluir."""
    with clients_lock:
        for username, client in clients.items():
            if client_groups.get(username) == group and client != exclude_socket:
                try:
                    send_packet(client, message)
                except Exception as e:
                    print(f"Error al enviar a {username}: {e}")

def update_user_list(group):
    """Envía a todos los clientes del grupo la lista actualizada de usuarios conectados."""
    with clients_lock:
        user_list = [u for u, g in client_groups.items() if g == group]
    message = {'type': 'user_list', 'users': user_list}
    data = pickle.dumps(message)
    encrypted_data = cipher_suite.encrypt(data)
    broadcast(encrypted_data, group)

def handle_client(client_socket, address):
    print(f"Nueva conexión desde {address}")
    username = None
    try:
        while True:
            raw_msglen = recvall(client_socket, 4)
            if not raw_msglen:
                break
            msglen = int.from_bytes(raw_msglen, byteorder='big')
            data = recvall(client_socket, msglen)
            if data is None:
                break

            try:
                decrypted_data = cipher_suite.decrypt(data)
                message = pickle.loads(decrypted_data)
            except Exception as e:
                print("Error al deserializar:", e)
                continue

            if message.get('type') == 'register':
                username = message.get('username')
                group = message.get('group', 'Grupo General')
                with clients_lock:
                    clients[username] = client_socket
                    client_groups[username] = group
                print(f"Usuario registrado: {username} en grupo {group}")
                update_user_list(group)
            elif message.get('type') == 'change_group':
                # Actualizar el grupo del usuario
                new_group = message.get('group', 'Grupo General')
                with clients_lock:
                    client_groups[username] = new_group
                print(f"Usuario {username} cambió al grupo {new_group}")
                update_user_list(new_group)
            elif message.get('type') == 'file':
                # Reenviar mensajes tipo 'file' a todos los clientes del mismo grupo
                group = client_groups.get(username, 'Grupo General')
                reserialized = pickle.dumps(message)
                encrypted_message = cipher_suite.encrypt(reserialized)
                broadcast(encrypted_message, group, exclude_socket=client_socket)
            else:
                # Si llega algún otro tipo de mensaje (por ejemplo, 'text'), se ignora ya que ahora se usa UDP multicast.
                pass
    except Exception as e:
        print(f"Error con el cliente {address}: {e}")
    finally:
        if username:
            with clients_lock:
                if username in clients:
                    del clients[username]
                if username in client_groups:
                    grupo_eliminado = client_groups[username]
                    del client_groups[username]
                    update_user_list(grupo_eliminado)
        client_socket.close()
        print(f"Conexión cerrada desde {address}")

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print(f"Servidor escuchando en {SERVER_HOST}:{SERVER_PORT}")

    while True:
        client_socket, address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, address), daemon=True)
        client_thread.start()

if __name__ == "__main__":
    main()
