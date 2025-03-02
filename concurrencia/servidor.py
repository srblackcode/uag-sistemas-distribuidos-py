import cv2
import socket
import pickle
import struct
from cryptography.fernet import Fernet

# Generar clave de cifrado
key = Fernet.generate_key()
cipher = Fernet(key)

# Configuración del servidor
HOST = '0.0.0.0'
PORT = 9999

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(5)
print(f"[*] Esperando conexión en {HOST}:{PORT}")

conn, addr = server_socket.accept()
print(f"[+] Conexión establecida con {addr}")
conn.sendall(key)  # Enviar clave de cifrado al cliente

cap = cv2.VideoCapture(0)  # Captura desde la cámara web

while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        break
    
    data = pickle.dumps(frame)
    encrypted_data = cipher.encrypt(data)
    message_size = struct.pack("Q", len(encrypted_data))
    conn.sendall(message_size + encrypted_data)
    
    cv2.imshow("Servidor - Enviando Video", frame)
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cap.release()
conn.close()
server_socket.close()
cv2.destroyAllWindows()