import sys
import socket
import threading
import json
import os
import base64
import hashlib
import time
from datetime import datetime
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class NetworkClient:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.username = None
        self.aes_key = None
        self.fernet = None
        self.lock = threading.Lock()

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)
            self.socket.connect((self.host, self.port))
            self.connected = True
            print("✓ Подключено к серверу")
            return True
        except Exception as e:
            print(f"✗ Ошибка подключения: {e}")
            return False

    def disconnect(self):
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.connected = False
        self.socket = None

    def send_sync_request(self, data, timeout=15):
        """Синхронная отправка запроса и получение ответа"""
        if not self.connected or not self.socket:
            print("Нет подключения к серверу")
            return None

        try:
            # Устанавливаем таймаут
            self.socket.settimeout(timeout)

            # Отправляем запрос
            json_data = json.dumps(data).encode()
            self.socket.send(len(json_data).to_bytes(4, 'big'))
            self.socket.send(json_data)

            # Получаем длину ответа
            length_data = self.socket.recv(4)
            if not length_data:
                print("Сервер закрыл соединение")
                return None

            response_length = int.from_bytes(length_data, 'big')

            # Получаем сам ответ
            response_data = b''
            while len(response_data) < response_length:
                chunk = self.socket.recv(min(4096, response_length - len(response_data)))
                if not chunk:
                    break
                response_data += chunk

            if len(response_data) != response_length:
                print("Неполный ответ от сервера")
                return None

            # Парсим ответ
            response = json.loads(response_data.decode('utf-8'))
            return response

        except socket.timeout:
            print("Таймаут при ожидании ответа")
            return None
        except ConnectionResetError:
            print("Соединение сброшено сервером")
            self.connected = False
            return None
        except Exception as e:
            print(f"Ошибка при отправке/получении данных: {e}")
            return None

    def register(self, username, email, password):
        username = username.strip()
        email = email.strip().lower()

        if len(username) < 3:
            return False, "Имя должно быть не менее 3 символов"

        if len(password) < 6:
            return False, "Пароль должен быть не менее 6 символов"

        if '@' not in email or '.' not in email:
            return False, "Некорректный email"

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        data = {
            'action': 'register',
            'username': username,
            'email': email,
            'password': password_hash
        }

        response = self.send_sync_request(data)

        if response is None:
            return False, "Ошибка соединения с сервером"

        if response.get('status') == 'success':
            self.username = username
            if 'encryption_key' in response:
                self.aes_key = base64.b64decode(response['encryption_key'])
                self.fernet = Fernet(base64.b64encode(self.aes_key[:32]))
            return True, "Регистрация успешна"
        else:
            error_msg = response.get('message', 'Неизвестная ошибка')
            return False, error_msg

    def login(self, username, password):
        username = username.strip()

        if not username or not password:
            return False, "Заполните все поля"

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        data = {
            'action': 'login',
            'username': username,
            'password': password_hash
        }

        response = self.send_sync_request(data)

        if response is None:
            return False, "Ошибка соединения с сервером"

        if response.get('status') == 'success':
            self.username = username
            if 'encryption_key' in response:
                self.aes_key = base64.b64decode(response['encryption_key'])
                self.fernet = Fernet(base64.b64encode(self.aes_key[:32]))
            return True, "Вход выполнен"
        else:
            error_msg = response.get('message', 'Неверные данные')
            return False, error_msg

    def send_message(self, receiver, message):
        data = {
            'action': 'send_message',
            'sender': self.username,
            'receiver': receiver,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }

        return self.send_sync_request(data)

    def get_messages(self, other_user):
        data = {
            'action': 'get_messages',
            'user1': self.username,
            'user2': other_user
        }

        return self.send_sync_request(data)

    def search_users(self, query):
        data = {
            'action': 'search_users',
            'query': query
        }

        return self.send_sync_request(data)

    def send_file(self, receiver, file_path):
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()

            if self.aes_key:
                cipher = AES.new(self.aes_key, AES.MODE_CBC)
                ct_bytes = cipher.encrypt(pad(file_data, AES.block_size))
                iv = cipher.iv
                encrypted_data = iv + ct_bytes
            else:
                encrypted_data = file_data

            file_name = os.path.basename(file_path)

            data = {
                'action': 'send_file',
                'sender': self.username,
                'receiver': receiver,
                'file_name': file_name,
                'file_data': base64.b64encode(encrypted_data).decode(),
                'timestamp': datetime.now().isoformat()
            }

            return self.send_sync_request(data)
        except Exception as e:
            print(f"Ошибка отправки файла: {e}")
            return None

    def start_voice_call(self, receiver):
        data = {
            'action': 'start_voice_call',
            'caller': self.username,
            'receiver': receiver
        }

        return self.send_sync_request(data)

    def update_profile(self, avatar_data=None, password=None):
        data = {
            'action': 'update_profile',
            'username': self.username,
            'avatar': avatar_data
        }

        if password:
            data['password'] = hashlib.sha256(password.encode()).hexdigest()

        return self.send_sync_request(data)

    def get_user_avatar(self, username):
        data = {
            'action': 'get_user_avatar',
            'username': username
        }

        return self.send_sync_request(data)


class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.network_client = NetworkClient()
        self.setWindowTitle("Secure Messenger - Вход")
        self.setFixedSize(400, 300)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        title = QLabel("Secure Messenger")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.connect_label = QLabel("Подключение...")
        self.connect_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.connect_label)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Имя пользователя")
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Пароль")
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.login_btn = QPushButton("Войти")
        self.login_btn.clicked.connect(self.login)
        layout.addWidget(self.login_btn)

        self.register_btn = QPushButton("Регистрация")
        self.register_btn.clicked.connect(self.open_register)
        layout.addWidget(self.register_btn)

        self.retry_btn = QPushButton("Повторить подключение")
        self.retry_btn.clicked.connect(self.connect_to_server)
        self.retry_btn.hide()
        layout.addWidget(self.retry_btn)

        self.setLayout(layout)
        self.connect_to_server()

    def connect_to_server(self):
        self.connect_label.setText("Подключение к серверу...")
        self.login_btn.setEnabled(False)
        self.register_btn.setEnabled(False)
        self.retry_btn.hide()
        QApplication.processEvents()

        if self.network_client.connect():
            self.connect_label.setText("✓ Подключено к серверу")
            self.connect_label.setStyleSheet("color: green")
            self.login_btn.setEnabled(True)
            self.register_btn.setEnabled(True)
        else:
            self.connect_label.setText("✗ Сервер недоступен")
            self.connect_label.setStyleSheet("color: red")
            self.retry_btn.show()

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()

        if not username or not password:
            QMessageBox.warning(self, "Ошибка", "Заполните все поля")
            return

        if not self.network_client.connected:
            QMessageBox.warning(self, "Ошибка", "Нет подключения к серверу")
            return

        self.login_btn.setEnabled(False)
        self.login_btn.setText("Вход...")
        QApplication.processEvents()

        success, message = self.network_client.login(username, password)

        if success:
            self.main_window = MainWindow(self.network_client)
            self.main_window.show()
            self.close()
        else:
            QMessageBox.warning(self, "Ошибка", message)
            self.login_btn.setEnabled(True)
            self.login_btn.setText("Войти")

    def open_register(self):
        if not self.network_client.connected:
            QMessageBox.warning(self, "Ошибка", "Нет подключения к серверу")
            return

        self.register_window = RegisterWindow(self.network_client, self)
        self.register_window.show()


class RegisterWindow(QWidget):
    def __init__(self, network_client, login_window):
        super().__init__()
        self.network_client = network_client
        self.login_window = login_window
        self.setWindowTitle("Регистрация")
        self.setFixedSize(400, 400)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        title = QLabel("Регистрация")
        title.setFont(QFont("Arial", 16))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Имя пользователя (мин. 3 символа)")
        layout.addWidget(self.username_input)

        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Email (только для регистрации)")
        layout.addWidget(self.email_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Пароль (мин. 6 символов)")
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.confirm_password = QLineEdit()
        self.confirm_password.setPlaceholderText("Подтвердите пароль")
        self.confirm_password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.confirm_password)

        self.register_btn = QPushButton("Зарегистрироваться")
        self.register_btn.clicked.connect(self.register)
        layout.addWidget(self.register_btn)

        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def register(self):
        username = self.username_input.text().strip()
        email = self.email_input.text().strip().lower()
        password = self.password_input.text()
        confirm = self.confirm_password.text()

        if len(username) < 3:
            self.status_label.setText("Имя должно быть не менее 3 символов")
            self.status_label.setStyleSheet("color: red")
            return

        if len(password) < 6:
            self.status_label.setText("Пароль должен быть не менее 6 символов")
            self.status_label.setStyleSheet("color: red")
            return

        if password != confirm:
            self.status_label.setText("Пароли не совпадают")
            self.status_label.setStyleSheet("color: red")
            return

        if '@' not in email or '.' not in email:
            self.status_label.setText("Некорректный email")
            self.status_label.setStyleSheet("color: red")
            return

        if not self.network_client.connected:
            self.status_label.setText("Нет подключения к серверу")
            self.status_label.setStyleSheet("color: red")
            return

        self.register_btn.setEnabled(False)
        self.register_btn.setText("Регистрация...")
        self.status_label.setText("")
        QApplication.processEvents()

        success, message = self.network_client.register(username, email, password)

        if success:
            self.status_label.setText("✓ " + message)
            self.status_label.setStyleSheet("color: green")
            QTimer.singleShot(1000, self.open_main_window)
        else:
            self.status_label.setText("✗ " + message)
            self.status_label.setStyleSheet("color: red")
            self.register_btn.setEnabled(True)
            self.register_btn.setText("Зарегистрироваться")

    def open_main_window(self):
        self.login_window.close()
        self.close()
        self.main_window = MainWindow(self.network_client)
        self.main_window.show()


class MainWindow(QMainWindow):
    def __init__(self, network_client):
        super().__init__()
        self.network_client = network_client
        self.username = network_client.username
        self.current_chat = None
        self.contacts = []  # Список контактов
        self.init_ui()

        # Загружаем контакты
        self.load_contacts()

    def init_ui(self):
        self.setWindowTitle(f"Secure Messenger - {self.username}")
        self.setGeometry(100, 100, 1200, 700)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout()
        central_widget.setLayout(main_layout)

        left_panel = self.create_left_panel()
        main_layout.addWidget(left_panel)

        self.chat_widget = self.create_chat_panel()
        main_layout.addWidget(self.chat_widget)

        self.create_menu()

    def create_left_panel(self):
        left_panel = QWidget()
        left_panel.setMaximumWidth(350)
        left_layout = QVBoxLayout()

        top_widget = QWidget()
        top_layout = QVBoxLayout()

        self.avatar_btn = QPushButton()
        self.avatar_btn.setIcon(QIcon("default_avatar.png"))
        self.avatar_btn.setIconSize(QSize(50, 50))
        self.avatar_btn.setFixedSize(60, 60)
        self.avatar_btn.setStyleSheet("border-radius: 30px;")
        self.avatar_btn.clicked.connect(self.open_profile_settings)
        top_layout.addWidget(self.avatar_btn, alignment=Qt.AlignCenter)

        self.username_label = QLabel(self.username)
        self.username_label.setAlignment(Qt.AlignCenter)
        self.username_label.setFont(QFont("Arial", 12, QFont.Bold))
        top_layout.addWidget(self.username_label)

        buttons = [
            ("Избранное", self.open_favorites),
            ("Поиск пользователей", self.search_users),
            ("Настройки приложения", self.open_app_settings)
        ]

        for text, callback in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(callback)
            top_layout.addWidget(btn)

        top_widget.setLayout(top_layout)
        left_layout.addWidget(top_widget)

        left_layout.addWidget(QLabel("Чаты:"))
        self.chat_list = QListWidget()
        self.chat_list.itemClicked.connect(self.open_chat)
        left_layout.addWidget(self.chat_list)

        status_widget = QWidget()
        status_layout = QVBoxLayout()

        self.status_label = QLabel("✓ Соединение установлено")
        self.status_label.setStyleSheet("color: green")
        status_layout.addWidget(self.status_label)

        self.ip_label = QLabel(f"Пользователь: {self.username}")
        status_layout.addWidget(self.ip_label)

        status_widget.setLayout(status_layout)
        left_layout.addWidget(status_widget)

        left_panel.setLayout(left_layout)
        return left_panel

    def create_chat_panel(self):
        chat_widget = QWidget()
        self.chat_layout = QVBoxLayout()

        header_widget = QWidget()
        header_layout = QHBoxLayout()

        self.chat_header = QLabel("Выберите чат")
        self.chat_header.setFont(QFont("Arial", 14, QFont.Bold))
        header_layout.addWidget(self.chat_header)

        self.call_btn = QPushButton("📞")
        self.call_btn.setFixedSize(40, 40)
        self.call_btn.clicked.connect(self.start_voice_call)
        self.call_btn.setEnabled(False)
        header_layout.addWidget(self.call_btn)

        self.file_btn = QPushButton("📎")
        self.file_btn.setFixedSize(40, 40)
        self.file_btn.clicked.connect(self.send_file)
        self.file_btn.setEnabled(False)
        header_layout.addWidget(self.file_btn)

        header_widget.setLayout(header_layout)
        self.chat_layout.addWidget(header_widget)

        self.messages_area = QTextEdit()
        self.messages_area.setReadOnly(True)
        self.chat_layout.addWidget(self.messages_area)

        input_widget = QWidget()
        input_layout = QHBoxLayout()

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Введите сообщение...")
        self.message_input.returnPressed.connect(self.send_message)
        input_layout.addWidget(self.message_input)

        self.send_btn = QPushButton("Отправить")
        self.send_btn.clicked.connect(self.send_message)
        input_layout.addWidget(self.send_btn)

        input_widget.setLayout(input_layout)
        self.chat_layout.addWidget(input_widget)

        chat_widget.setLayout(self.chat_layout)
        return chat_widget

    def create_menu(self):
        menubar = self.menuBar()

        file_menu = menubar.addMenu('Файл')
        exit_action = QAction('Выход', self)
        exit_action.triggered.connect(self.close_application)
        file_menu.addAction(exit_action)

        tools_menu = menubar.addMenu('Инструменты')
        refresh_action = QAction('Обновить контакты', self)
        refresh_action.triggered.connect(self.load_contacts)
        tools_menu.addAction(refresh_action)

    def close_application(self):
        self.network_client.disconnect()
        self.close()

    def load_contacts(self):
        self.chat_list.clear()
        # Загружаем контакты из локального хранилища
        try:
            if os.path.exists(f"{self.username}_contacts.json"):
                with open(f"{self.username}_contacts.json", 'r') as f:
                    self.contacts = json.load(f)
                    for contact in self.contacts:
                        self.chat_list.addItem(contact)
        except:
            self.contacts = []

    def save_contacts(self):
        try:
            with open(f"{self.username}_contacts.json", 'w') as f:
                json.dump(self.contacts, f)
        except:
            pass

    def add_contact(self, username):
        if username != self.username and username not in self.contacts:
            self.contacts.append(username)
            self.chat_list.addItem(username)
            self.save_contacts()

    def open_profile_settings(self):
        dialog = ProfileSettingsDialog(self.network_client, self.username, self)
        dialog.exec_()

    def open_favorites(self):
        self.current_chat = "Избранное"
        self.chat_header.setText("Избранное")
        self.messages_area.clear()
        self.messages_area.append("Здесь будут избранные сообщения")
        self.call_btn.setEnabled(False)
        self.file_btn.setEnabled(False)

    def search_users(self):
        dialog = SearchDialog(self.network_client, self)
        if dialog.exec_():
            selected_user = dialog.get_selected_user()
            if selected_user:
                self.add_contact(selected_user)
                self.open_chat_with_user(selected_user)

    def open_app_settings(self):
        dialog = AppSettingsDialog()
        dialog.exec_()

    def open_chat(self, item):
        contact = item.text()
        self.open_chat_with_user(contact)

    def open_chat_with_user(self, user):
        self.current_chat = user
        self.chat_header.setText(f"Чат с {user}")
        self.messages_area.clear()

        response = self.network_client.get_messages(user)
        if response and response.get('status') == 'success':
            messages = response.get('messages', [])
            for msg in messages:
                sender = msg.get('sender')
                text = msg.get('message')
                timestamp = msg.get('timestamp', '')[:19]
                self.messages_area.append(f"[{timestamp}] {sender}: {text}")

        self.call_btn.setEnabled(True)
        self.file_btn.setEnabled(True)

    def send_message(self):
        message = self.message_input.text()
        if message and self.current_chat and self.current_chat != "Избранное":
            response = self.network_client.send_message(self.current_chat, message)
            if response and response.get('status') == 'success':
                timestamp = datetime.now().strftime("%H:%M")
                self.messages_area.append(f"[{timestamp}] Вы: {message}")
                self.message_input.clear()

    def send_file(self):
        if not self.current_chat or self.current_chat == "Избранное":
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self, "Выберите файл", "", "Все файлы (*)"
        )

        if file_path:
            response = self.network_client.send_file(self.current_chat, file_path)
            if response and response.get('status') == 'success':
                timestamp = datetime.now().strftime("%H:%M")
                file_name = os.path.basename(file_path)
                self.messages_area.append(f"[{timestamp}] Вы отправили файл: {file_name}")

    def start_voice_call(self):
        if not self.current_chat or self.current_chat == "Избранное":
            return

        response = self.network_client.start_voice_call(self.current_chat)
        if response and response.get('status') == 'success':
            QMessageBox.information(self, "Звонок", f"Звонок пользователю {self.current_chat} начат")
        else:
            QMessageBox.warning(self, "Ошибка", "Не удалось начать звонок")

    def update_avatar(self, avatar_data):
        if avatar_data:
            try:
                # Декодируем base64 и создаем QPixmap
                avatar_bytes = base64.b64decode(avatar_data)
                pixmap = QPixmap()
                pixmap.loadFromData(avatar_bytes)
                pixmap = pixmap.scaled(60, 60, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                self.avatar_btn.setIcon(QIcon(pixmap))
            except Exception as e:
                print(f"Ошибка обновления аватара: {e}")


class ProfileSettingsDialog(QDialog):
    def __init__(self, network_client, username, main_window):
        super().__init__()
        self.network_client = network_client
        self.username = username
        self.main_window = main_window
        self.setWindowTitle("Настройки профиля")
        self.setFixedSize(400, 450)
        self.avatar_data = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        avatar_layout = QHBoxLayout()
        self.avatar_label = QLabel()
        # Пытаемся загрузить текущий аватар
        response = self.network_client.get_user_avatar(self.username)
        if response and response.get('status') == 'success' and response.get('avatar'):
            try:
                avatar_bytes = base64.b64decode(response['avatar'])
                pixmap = QPixmap()
                pixmap.loadFromData(avatar_bytes)
                pixmap = pixmap.scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                self.avatar_label.setPixmap(pixmap)
            except:
                self.avatar_label.setPixmap(QPixmap("default_avatar.png").scaled(100, 100))
        else:
            self.avatar_label.setPixmap(QPixmap("default_avatar.png").scaled(100, 100))
        avatar_layout.addWidget(self.avatar_label)

        self.change_avatar_btn = QPushButton("Сменить аватар")
        self.change_avatar_btn.clicked.connect(self.change_avatar)
        avatar_layout.addWidget(self.change_avatar_btn)

        layout.addLayout(avatar_layout)

        layout.addWidget(QLabel("Имя пользователя:"))
        self.username_edit = QLineEdit(self.username)
        self.username_edit.setReadOnly(True)
        layout.addWidget(self.username_edit)

        layout.addWidget(QLabel("Новый пароль:"))
        self.new_password = QLineEdit()
        self.new_password.setEchoMode(QLineEdit.Password)
        self.new_password.setPlaceholderText("Оставьте пустым, если не хотите менять")
        layout.addWidget(self.new_password)

        layout.addWidget(QLabel("Подтвердите пароль:"))
        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.confirm_password)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self.save_changes)
        buttons.rejected.connect(self.reject)

        layout.addWidget(buttons)
        self.setLayout(layout)

    def change_avatar(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Выберите аватар", "", "Images (*.png *.jpg *.jpeg)"
        )
        if file_name:
            try:
                with open(file_name, 'rb') as f:
                    self.avatar_data = base64.b64encode(f.read()).decode()

                # Показываем предпросмотр
                pixmap = QPixmap(file_name).scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                self.avatar_label.setPixmap(pixmap)
            except Exception as e:
                QMessageBox.warning(self, "Ошибка", f"Не удалось загрузить аватар: {e}")

    def save_changes(self):
        new_password = self.new_password.text()
        confirm = self.confirm_password.text()

        if new_password and new_password != confirm:
            QMessageBox.warning(self, "Ошибка", "Пароли не совпадают")
            return

        # Отправляем на сервер
        response = self.network_client.update_profile(
            avatar_data=self.avatar_data,
            password=new_password if new_password else None
        )

        if response and response.get('status') == 'success':
            QMessageBox.information(self, "Успех", "Профиль обновлен")

            # Обновляем аватар в главном окне
            if self.avatar_data:
                self.main_window.update_avatar(self.avatar_data)

            self.accept()
        else:
            error_msg = response.get('message', 'Неизвестная ошибка') if response else 'Ошибка соединения'
            QMessageBox.warning(self, "Ошибка", f"Не удалось обновить профиль: {error_msg}")


class AppSettingsDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Настройки приложения")
        self.setFixedSize(300, 200)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Тема оформления:"))

        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Светлая", "Темная"])
        layout.addWidget(self.theme_combo)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self.save_settings)
        buttons.rejected.connect(self.reject)

        layout.addWidget(buttons)
        self.setLayout(layout)

    def save_settings(self):
        theme = self.theme_combo.currentText()
        QMessageBox.information(self, "Успех", f"Тема изменена на: {theme}")
        self.accept()


class SearchDialog(QDialog):
    def __init__(self, network_client, main_window):
        super().__init__()
        self.network_client = network_client
        self.main_window = main_window
        self.selected_user = None
        self.setWindowTitle("Поиск пользователей")
        self.setFixedSize(400, 400)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Поиск по имени пользователя:"))

        self.search_input = QLineEdit()
        layout.addWidget(self.search_input)

        self.search_btn = QPushButton("Найти")
        self.search_btn.clicked.connect(self.search)
        layout.addWidget(self.search_btn)

        self.results_list = QListWidget()
        self.results_list.itemDoubleClicked.connect(self.select_user)
        layout.addWidget(self.results_list)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def search(self):
        query = self.search_input.text()
        if query:
            self.results_list.clear()
            response = self.network_client.search_users(query)
            if response and response.get('status') == 'success':
                users = response.get('users', [])
                for user in users:
                    username = user['username']
                    if username != self.main_window.username:  # Не показывать себя
                        self.results_list.addItem(username)

    def select_user(self, item):
        text = item.text()
        self.selected_user = text

    def get_selected_user(self):
        return self.selected_user


if __name__ == "__main__":
    app = QApplication(sys.argv)

    login_window = LoginWindow()
    login_window.show()

    sys.exit(app.exec_())