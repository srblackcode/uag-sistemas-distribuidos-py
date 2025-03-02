import cv2
import socket
import pickle
import struct
from cryptography.fernet import Fernet

# Configuración del cliente
HOST = '127.0.0.1'
PORT = 9999

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

key = client_socket.recv(1024)  # Recibir clave de cifrado del servidor
cipher = Fernet(key)

data = b""
payload_size = struct.calcsize("Q")

while True:
    while len(data) < payload_size:
        packet = client_socket.recv(4096)
        if not packet:
            break
        data += packet
    
    packed_msg_size = data[:payload_size]
    data = data[payload_size:]
    msg_size = struct.unpack("Q", packed_msg_size)[0]
    
    while len(data) < msg_size:
        data += client_socket.recv(4096)
    
    encrypted_frame_data = data[:msg_size]
    data = data[msg_size:]
    frame_data = cipher.decrypt(encrypted_frame_data)
    frame = pickle.loads(frame_data)
    
    cv2.imshow("Cliente - Recibiendo Video", frame)
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

client_socket.close()
cv2.destroyAllWindows()
