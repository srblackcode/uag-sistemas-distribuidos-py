import sys
import socket
import threading
import pickle
import os
from hashlib import sha256
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QLineEdit, QPushButton, QLabel, QFileDialog, QMessageBox, QInputDialog, QComboBox, QProgressBar
)
from PyQt5.QtCore import Qt
from cryptography.fernet import Fernet

# Parámetros de conexión y cifrado
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345
ENCRYPTION_KEY = b'R1dJWWdUbXp1cVdpWlZoNUR5eEx4c3BYdExQeU5yYm0='
cipher_suite = Fernet(ENCRYPTION_KEY)

# Socket TCP para registro, notificaciones y transferencia de archivos
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Constantes para comunicación multicast UDP (para mensajes de texto)
MULTICAST_GROUP = '224.1.1.1'
MULTICAST_PORT = 5007

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

class ChatClient(QWidget):
    def __init__(self, username, group):
        super().__init__()
        self.username = username
        self.group = group
        self.running = True
        self.file_buffers = {}
        self.init_ui()
        self.setup_udp_multicast()
        # Hilo para recibir mensajes UDP (texto)
        threading.Thread(target=self.receive_udp_messages, daemon=True).start()
        # Hilo para recibir mensajes TCP (archivo, actualización de usuarios, etc.)
        threading.Thread(target=self.receive_tcp_messages, daemon=True).start()

    def init_ui(self):
        self.setWindowTitle(f"Mensajero - {self.username} ({self.group})")
        self.resize(500, 650)

        layout = QVBoxLayout(self)

        # Encabezado: nombre del grupo, imagen y botón para cambiar de grupo
        header_layout = QHBoxLayout()
        self.header_label = QLabel(self.group)
        self.header_label.setStyleSheet("background-color: #075E54; color: white; font: bold 16pt; padding: 10px;")
        header_layout.addWidget(self.header_label)

        self.image_label = QLabel()
        pixmap = QPixmap("avatar.png")  # Asegúrate de que el archivo exista o actualiza la ruta
        if not pixmap.isNull():
            pixmap = pixmap.scaled(50, 50, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.image_label.setPixmap(pixmap)
        else:
            self.image_label.setText("[Foto]")
        self.image_label.setStyleSheet("background-color: #075E54; padding: 10px; border: 1px solid white;")
        header_layout.addWidget(self.image_label, alignment=Qt.AlignRight)

        self.change_group_button = QPushButton("Cambiar Grupo")
        self.change_group_button.clicked.connect(self.change_group)
        header_layout.addWidget(self.change_group_button)
        layout.addLayout(header_layout)

        # Área de chat
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        layout.addWidget(self.chat_area)

        # Barra de progreso para el envío de archivos
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        # Panel inferior: entrada de texto, lista de emojis y botones
        input_layout = QHBoxLayout()
        self.input_field = QLineEdit()
        self.input_field.returnPressed.connect(self.send_text_message)
        input_layout.addWidget(self.input_field)

        self.emoji_combo = QComboBox()
        self.emoji_combo.addItem("Emojis")
        emoji_list = [
            "😀", "😃", "😄", "😁", "😆", "😅", "😂", "🤣", "😊", "😇",
            "🙂", "🙃", "😉", "😌", "😍", "🥰", "😘", "😗", "😙", "😚",
            "😋", "😛", "😝", "😜", "🤪", "🤨", "🧐", "🤓", "😎", "🤩",
            "🥳", "😏", "😒", "😞", "😔", "😟", "😕", "🙁", "☹️", "😣"
        ]
        self.emoji_combo.addItems(emoji_list)
        self.emoji_combo.currentIndexChanged.connect(self.insert_emoji)
        input_layout.addWidget(self.emoji_combo)

        self.send_button = QPushButton("Enviar")
        self.send_button.clicked.connect(self.send_text_message)
        input_layout.addWidget(self.send_button)

        self.file_button = QPushButton("Adjuntar")
        self.file_button.clicked.connect(self.send_file)
        input_layout.addWidget(self.file_button)

        layout.addLayout(input_layout)

    def setup_udp_multicast(self):
        """Configura el socket UDP para unirse al grupo multicast."""
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        # Permitir reutilización de la dirección
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            # SO_REUSEPORT no está disponible en algunos sistemas
            pass
        try:
            self.udp_socket.bind(('', MULTICAST_PORT))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo unir al grupo multicast: {e}")
            sys.exit(1)
        mreq = socket.inet_aton(MULTICAST_GROUP) + socket.inet_aton('0.0.0.0')
        self.udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)


    def insert_emoji(self, index):
        if index == 0:
            return
        emoji = self.emoji_combo.itemText(index)
        current_text = self.input_field.text()
        self.input_field.setText(current_text + emoji)
        self.emoji_combo.setCurrentIndex(0)

    def display_message(self, message):
        self.chat_area.append(message)

    def send_text_message(self):
        message_text = self.input_field.text().strip()
        if not message_text:
            return

        # Reemplazo básico de cadenas por emojis
        message_text = message_text.replace(":)", "😊").replace(":(", "☹️")
        message = {
            'type': 'text',
            'sender': self.username,
            'group': self.group,
            'content': message_text
        }
        try:
            data = pickle.dumps(message)
            encrypted_data = cipher_suite.encrypt(data)
            # Enviar el mensaje mediante multicast UDP
            self.udp_socket.sendto(encrypted_data, (MULTICAST_GROUP, MULTICAST_PORT))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo enviar el mensaje: {e}")
            return
        self.input_field.clear()
        self.display_message(f"Tú: {message_text}")

    def send_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo")
        if not file_path:
            return
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo abrir el archivo: {e}")
            return

        # Calcular checksum para verificar integridad en el receptor
        file_checksum = sha256(file_data).hexdigest()

        # Cifrar el archivo y fragmentarlo
        encrypted_file_data = cipher_suite.encrypt(file_data)
        chunk_size = 4096
        total_chunks = (len(encrypted_file_data) + chunk_size - 1) // chunk_size

        # Enviar metadatos del archivo (chunk_index = 0)
        message = {
            'type': 'file',
            'sender': self.username,
            'group': self.group,
            'filename': os.path.basename(file_path),
            'total_chunks': total_chunks,
            'chunk_index': 0,
            'checksum': file_checksum,
            'content': None
        }
        data = pickle.dumps(message)
        encrypted_meta = cipher_suite.encrypt(data)
        try:
            send_packet(client_socket, encrypted_meta)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo enviar metadatos: {e}")
            return

        # Enviar cada fragmento cifrado y actualizar la barra de progreso
        for i in range(total_chunks):
            chunk = encrypted_file_data[i*chunk_size : (i+1)*chunk_size]
            message = {
                'type': 'file',
                'sender': self.username,
                'group': self.group,
                'filename': os.path.basename(file_path),
                'total_chunks': total_chunks,
                'chunk_index': i+1,
                'content': chunk,
                'checksum': None  # Solo se envía en metadatos
            }
            data = pickle.dumps(message)
            encrypted_chunk = cipher_suite.encrypt(data)
            try:
                send_packet(client_socket, encrypted_chunk)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"No se pudo enviar el fragmento {i+1}: {e}")
                return
            progress = int((i+1) / total_chunks * 100)
            self.progress_bar.setValue(progress)

        self.display_message(f"Tú has enviado el archivo: {os.path.basename(file_path)}")
        self.progress_bar.setValue(0)

    def receive_udp_messages(self):
        """Hilo para recibir mensajes de texto vía UDP multicast."""
        while self.running:
            try:
                data, addr = self.udp_socket.recvfrom(65536)
                decrypted_data = cipher_suite.decrypt(data)
                message = pickle.loads(decrypted_data)
                # Procesar solo mensajes del grupo actual
                if message.get('group') == self.group and message.get('type') == 'text':
                    sender = message.get('sender')
                    content = message.get('content')
                    self.display_message(f"{sender}: {content}")
            except Exception as e:
                print("Error recibiendo UDP:", e)

    def receive_tcp_messages(self):
        """Hilo para recibir mensajes vía TCP (archivo, actualizaciones de usuarios, etc.)."""
        while self.running:
            try:
                raw_msglen = recvall(client_socket, 4)
                if not raw_msglen:
                    break
                msglen = int.from_bytes(raw_msglen, byteorder='big')
                data = recvall(client_socket, msglen)
                if data is None:
                    break
                decrypted_data = cipher_suite.decrypt(data)
                message = pickle.loads(decrypted_data)
                if message.get('type') == 'user_list':
                    users = message.get('users')
                    self.display_message(f"Usuarios conectados: {', '.join(users)}")
                elif message.get('type') == 'file':
                    self.handle_file_message(message)
            except Exception as e:
                print(f"Error recibiendo mensaje TCP: {e}")
                break

    def handle_file_message(self, message):
        filename = message.get('filename')
        total_chunks = message.get('total_chunks')
        chunk_index = message.get('chunk_index')
        content = message.get('content')
        sender = message.get('sender')
        expected_checksum = message.get('checksum', None)

        if chunk_index == 0:
            self.file_buffers[filename] = {
                'total_chunks': total_chunks,
                'chunks': {},
                'checksum': expected_checksum
            }
            self.display_message(f"Recibiendo archivo '{filename}' de {sender}...")
        else:
            if filename not in self.file_buffers:
                self.file_buffers[filename] = {
                    'total_chunks': total_chunks,
                    'chunks': {},
                    'checksum': None
                }
            self.file_buffers[filename]['chunks'][chunk_index] = content

            if len(self.file_buffers[filename]['chunks']) == total_chunks:
                chunks = [self.file_buffers[filename]['chunks'][i+1] for i in range(total_chunks)]
                encrypted_file = b"".join(chunks)
                try:
                    file_data = cipher_suite.decrypt(encrypted_file)
                    # Verificar integridad con checksum si se recibió el valor
                    if self.file_buffers[filename]['checksum']:
                        actual_checksum = sha256(file_data).hexdigest()
                        if actual_checksum != self.file_buffers[filename]['checksum']:
                            self.display_message(f"Error: Checksum no coincide para '{filename}'.")
                            return
                    with open("recibido_" + filename, "wb") as f:
                        f.write(file_data)
                    self.display_message(f"Archivo '{filename}' recibido y guardado como 'recibido_{filename}'")
                except Exception as e:
                    self.display_message(f"Error al descifrar el archivo '{filename}': {e}")
                del self.file_buffers[filename]

    def change_group(self):
        new_group, ok = QInputDialog.getText(self, "Cambiar Grupo", "Ingresa el nuevo nombre del grupo:")
        if ok and new_group:
            self.group = new_group
            self.setWindowTitle(f"Mensajero - {self.username} ({self.group})")
            self.header_label.setText(self.group)
            # Enviar mensaje de cambio de grupo al servidor vía TCP
            message = {
                'type': 'change_group',
                'username': self.username,
                'group': self.group
            }
            data = pickle.dumps(message)
            encrypted_data = cipher_suite.encrypt(data)
            try:
                send_packet(client_socket, encrypted_data)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"No se pudo cambiar de grupo: {e}")

def main():
    app = QApplication(sys.argv)
    username, ok = QInputDialog.getText(None, "Usuario", "Ingresa tu nombre de usuario:")
    if not ok or not username:
        return
    group, ok = QInputDialog.getText(None, "Grupo", "Ingresa el nombre del grupo (por defecto 'Grupo General'):")
    if not ok or not group:
        group = "Grupo General"
    try:
        client_socket.connect((SERVER_HOST, SERVER_PORT))
    except Exception as e:
        QMessageBox.critical(None, "Error", f"No se pudo conectar al servidor: {e}")
        return

    # Enviar mensaje de registro al servidor vía TCP
    message = {
        'type': 'register',
        'username': username,
        'group': group
    }
    data = pickle.dumps(message)
    encrypted_data = cipher_suite.encrypt(data)
    send_packet(client_socket, encrypted_data)

    chat_client = ChatClient(username, group)
    chat_client.show()
    app.exec_()
    chat_client.running = False
    client_socket.close()

if __name__ == "__main__":
    main()
