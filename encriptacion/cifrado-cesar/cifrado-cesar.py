import socket
import getpass
import psycopg2

def connect_db():
    return psycopg2.connect(
        dbname="msegdb",
        user="postgres",
        password="root",
        host="localhost",
        port="5433"
    )

def authenticate_user(username, password):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
    user = cursor.fetchone()
    conn.close()
    return user is not None

def cesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char
    return result

def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 12345))
    server_socket.listen(1)
    print("Esperando conexión...")
    conn, addr = server_socket.accept()
    print(f"Conexión establecida con {addr}")
    
    while True:
        data = conn.recv(1024).decode()
        if not data:
            break
        print(f"Mensaje cifrado: {data}")
        print(f"Mensaje decodificado: {cesar_cipher(data, -3)}")
    
    conn.close()

def client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 12345))
    usuario = input("Ingrese usuario: ")
    contraseña = getpass.getpass("Ingrese contraseña: ")
    if authenticate_user(usuario, contraseña):
        while True:
            message = input("Mensaje a enviar: ")
            encrypted_message = cesar_cipher(message, 3)
            print(f"Mensaje codificado: {encrypted_message}")
            client_socket.send(encrypted_message.encode())
    else:
        print("Autenticación fallida.")
    client_socket.close()

if __name__ == "__main__":
    role = input("Ingrese 's' para servidor o 'c' para cliente: ")
    if role == 's':
        server()
    elif role == 'c':
        client()
    else:
        print("Rol no válido.")