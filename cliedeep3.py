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
import pickle
import re

# Локализация
TRANSLATIONS = {
    'ru': {
        'app_title': 'Secure Messenger',
        'login_title': 'Secure Messenger - Вход',
        'register_title': 'Регистрация',
        'main_title': 'Secure Messenger - {username}',
        'connect_label': 'Подключение...',
        'connected': '✓ Подключено к серверу',
        'disconnected': '✗ Сервер недоступен',
        'username_placeholder': 'Имя пользователя',
        'password_placeholder': 'Пароль',
        'remember_me': 'Запомнить меня',
        'login_btn': 'Войти',
        'register_btn': 'Регистрация',
        'retry_btn': 'Повторить подключение',
        'username_error': 'Заполните имя пользователя',
        'password_error': 'Заполните пароль',
        'connection_error': 'Нет подключения к серверу',
        'logging_in': 'Вход...',
        'registration': 'Регистрация...',
        'username_min': 'Имя должно быть не менее 3 символов',
        'password_min': 'Пароль должен быть не менее 6 символов',
        'email_error': 'Некорректный email',
        'passwords_match': 'Пароли не совпадают',
        'chats': 'Чаты:',
        'select_chat': 'Выберите чат',
        'chat_with': 'Чат с {user}',
        'message_placeholder': 'Введите сообщение...',
        'send_btn': 'Отправить',
        'connection_ok': '✓ Соединение установлено',
        'connection_lost': '✗ Соединение потеряно',
        'reconnect': 'Переподключиться',
        'settings': 'Настройки',
        'theme': 'Сменить тему',
        'logout': 'Выйти',
        'tools': 'Инструменты',
        'refresh_contacts': 'Обновить контакты',
        'search_users': 'Поиск пользователей',
        'notes': 'Заметки',
        'administration': 'Администрация',
        'online': '●',
        'send_file': 'Отправить файл',
        'start_call': 'Начать звонок',
        'profile_settings': 'Настройки профиля',
        'change_avatar': 'Сменить аватар',
        'new_password': 'Новый пароль',
        'confirm_password': 'Подтвердите пароль',
        'save': 'Сохранить',
        'cancel': 'Отмена',
        'search_placeholder': 'Имя пользователя',
        'search_btn': 'Найти',
        'no_users': 'Пользователи не найдены',
        'search_error': 'Нет подключения к серверу',
        'add_contact': 'Добавить контакт',
        'already_contact': 'Этот пользователь уже есть в ваших контактах',
        'cant_add_self': 'Нельзя добавить себя в контакты',
        'file_sent': 'Файл отправлен',
        'file_error': 'Не удалось отправить файл',
        'call_started': 'Звонок начат',
        'call_error': 'Не удалось начать звонок',
        'message_sent': 'Сообщение отправлено',
        'message_error': 'Не удалось отправить сообщение',
        'logout_confirm': 'Вы уверены, что хотите выйти из аккаунта?',
        'theme_changed': 'Тема изменена',
        'profile_updated': 'Профиль обновлен',
        'profile_error': 'Не удалось обновить профиль',
        'broadcast_notification': 'Уведомление',
        'incoming_call': 'Входящий звонок',
        'accept_call': 'Принять',
        'reject_call': 'Отклонить',
        'call_with': 'Звонок с {user}',
        'end_call': 'Завершить звонок',
        'mute': 'Без звука',
        'unmute': 'Включить звук',
        'call_ended': 'Звонок завершен',
    },
    'en': {
        'app_title': 'Secure Messenger',
        'login_title': 'Secure Messenger - Login',
        'register_title': 'Registration',
        'main_title': 'Secure Messenger - {username}',
        'connect_label': 'Connecting...',
        'connected': '✓ Connected to server',
        'disconnected': '✗ Server unavailable',
        'username_placeholder': 'Username',
        'password_placeholder': 'Password',
        'remember_me': 'Remember me',
        'login_btn': 'Login',
        'register_btn': 'Register',
        'retry_btn': 'Retry connection',
        'username_error': 'Enter username',
        'password_error': 'Enter password',
        'connection_error': 'No connection to server',
        'logging_in': 'Logging in...',
        'registration': 'Registering...',
        'username_min': 'Username must be at least 3 characters',
        'password_min': 'Password must be at least 6 characters',
        'email_error': 'Invalid email',
        'passwords_match': 'Passwords do not match',
        'chats': 'Chats:',
        'select_chat': 'Select chat',
        'chat_with': 'Chat with {user}',
        'message_placeholder': 'Type a message...',
        'send_btn': 'Send',
        'connection_ok': '✓ Connection established',
        'connection_lost': '✗ Connection lost',
        'reconnect': 'Reconnect',
        'settings': 'Settings',
        'theme': 'Change theme',
        'logout': 'Logout',
        'tools': 'Tools',
        'refresh_contacts': 'Refresh contacts',
        'search_users': 'Search users',
        'notes': 'Notes',
        'administration': 'Administration',
        'online': '●',
        'send_file': 'Send file',
        'start_call': 'Start call',
        'profile_settings': 'Profile Settings',
        'change_avatar': 'Change avatar',
        'new_password': 'New password',
        'confirm_password': 'Confirm password',
        'save': 'Save',
        'cancel': 'Cancel',
        'search_placeholder': 'Username',
        'search_btn': 'Search',
        'no_users': 'No users found',
        'search_error': 'No connection to server',
        'add_contact': 'Add contact',
        'already_contact': 'This user is already in your contacts',
        'cant_add_self': 'Cannot add yourself as contact',
        'file_sent': 'File sent',
        'file_error': 'Failed to send file',
        'call_started': 'Call started',
        'call_error': 'Failed to start call',
        'message_sent': 'Message sent',
        'message_error': 'Failed to send message',
        'logout_confirm': 'Are you sure you want to logout?',
        'theme_changed': 'Theme changed',
        'profile_updated': 'Profile updated',
        'profile_error': 'Failed to update profile',
        'broadcast_notification': 'Notification',
        'incoming_call': 'Incoming call',
        'accept_call': 'Accept',
        'reject_call': 'Reject',
        'call_with': 'Call with {user}',
        'end_call': 'End call',
        'mute': 'Mute',
        'unmute': 'Unmute',
        'call_ended': 'Call ended',
    }
}


class Translator:
    def __init__(self, language='ru'):
        self.language = language
        self.translations = TRANSLATIONS.get(language, TRANSLATIONS['ru'])

    def tr(self, key, **kwargs):
        text = self.translations.get(key, key)
        if kwargs:
            try:
                text = text.format(**kwargs)
            except:
                pass
        return text


class NetworkClient:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.username = None
        self.password_hash = None
        self.aes_key = None
        self.fernet = None
        self.lock = threading.Lock()
        self.message_callback = None
        self.receive_thread = None
        self.stop_receiving = False
        self.buffer_size = 8192
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 3

    def connect(self):
        try:
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.settimeout(10)
            self.socket.connect((self.host, self.port))
            self.socket.settimeout(30)
            self.connected = True
            self.stop_receiving = False
            self.reconnect_attempts = 0
            print("✓ Подключено к серверу")
            return True
        except Exception as e:
            print(f"✗ Ошибка подключения: {e}")
            self.connected = False
            return False

    def disconnect(self):
        self.stop_receiving = True
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.socket = None

    def start_receiving(self):
        if self.receive_thread and self.receive_thread.is_alive():
            return

        self.stop_receiving = False
        self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receive_thread.start()

    def receive_messages(self):
        while self.connected and not self.stop_receiving:
            try:
                if self.socket is None:
                    time.sleep(1)
                    continue

                self.socket.settimeout(5)

                length_data = self._recv_exact(4)
                if not length_data:
                    time.sleep(0.5)
                    continue

                message_length = int.from_bytes(length_data, 'big')
                if message_length <= 0 or message_length > 10 * 1024 * 1024:
                    continue

                data = self._recv_exact(message_length)
                if not data:
                    continue

                try:
                    response = json.loads(data.decode('utf-8', errors='ignore'))
                except json.JSONDecodeError as e:
                    print(f"Ошибка декодирования JSON: {e}")
                    continue

                if response.get('type') == 'push':
                    if self.message_callback:
                        self.message_callback(response)
                elif response.get('action') == 'ping':
                    self._send_heartbeat()

            except socket.timeout:
                continue
            except ConnectionResetError:
                print("Соединение сброшено сервером")
                self.connected = False
                break
            except Exception as e:
                if self.connected and not self.stop_receiving:
                    print(f"Ошибка при приеме сообщений: {e}")
                    self.connected = False
                    break

    def _recv_exact(self, n):
        if self.socket is None:
            return None

        data = b''
        while len(data) < n:
            try:
                chunk = self.socket.recv(min(self.buffer_size, n - len(data)))
                if not chunk:
                    return None
                data += chunk
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Ошибка приема: {e}")
                return None
        return data

    def _send_heartbeat(self):
        try:
            if self.socket:
                heartbeat = json.dumps({'action': 'ping'}).encode()
                self.socket.sendall(len(heartbeat).to_bytes(4, 'big'))
                self.socket.sendall(heartbeat)
        except:
            pass

    def send_request(self, data, timeout=15):
        if not self.connected or self.socket is None:
            print("Нет подключения к серверу")
            return None

        try:
            self.socket.settimeout(timeout)

            json_data = json.dumps(data).encode()

            try:
                self.socket.sendall(len(json_data).to_bytes(4, 'big'))
            except Exception as e:
                print(f"Ошибка отправки длины: {e}")
                self.connected = False
                return None

            try:
                self.socket.sendall(json_data)
            except Exception as e:
                print(f"Ошибка отправки данных: {e}")
                self.connected = False
                return None

            length_data = self._recv_exact(4)
            if not length_data:
                print("Сервер закрыл соединение")
                self.connected = False
                return None

            response_length = int.from_bytes(length_data, 'big')
            if response_length <= 0 or response_length > 10 * 1024 * 1024:
                print(f"Некорректная длина ответа: {response_length}")
                return None

            response_data = self._recv_exact(response_length)
            if not response_data:
                print("Неполный ответ от сервера")
                return None

            response = json.loads(response_data.decode('utf-8', errors='ignore'))
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
            self.connected = False
            return None

    def register(self, username, email, password):
        username = username.strip()
        email = email.strip().lower()

        if len(username) < 3:
            return False, "Имя должно быть не менее 3 символов"

        if len(password) < 6:
            return False, "Пароль должен быть не менее 6 символов"

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return False, "Некорректный email"

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        data = {
            'action': 'register',
            'username': username,
            'email': email,
            'password': password_hash
        }

        response = self.send_request(data)

        if response is None:
            return False, "Ошибка соединения с сервером"

        if response.get('status') == 'success':
            self.username = username
            self.password_hash = password_hash
            if 'encryption_key' in response:
                encryption_key = response['encryption_key']
                try:
                    self.fernet = Fernet(encryption_key.encode())
                    self.aes_key = encryption_key.encode()[:32]
                    if len(self.aes_key) < 32:
                        self.aes_key = self.aes_key.ljust(32, b'0')
                except Exception as e:
                    print(f"Ошибка создания ключа: {e}")
                    return False, "Ошибка создания ключа шифрования"
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

        response = self.send_request(data)

        if response is None:
            return False, "Ошибка соединения с сервером"

        if response.get('status') == 'success':
            self.username = username
            self.password_hash = password_hash
            if 'encryption_key' in response:
                encryption_key = response['encryption_key']
                try:
                    self.fernet = Fernet(encryption_key.encode())
                    self.aes_key = encryption_key.encode()[:32]
                    if len(self.aes_key) < 32:
                        self.aes_key = self.aes_key.ljust(32, b'0')
                except Exception as e:
                    print(f"Ошибка создания ключа: {e}")
                    return False, "Ошибка создания ключа шифрования"
            return True, "Вход выполнен"
        else:
            error_msg = response.get('message', 'Неверные данные')
            return False, error_msg

    def reconnect_and_login(self):
        self.disconnect()
        time.sleep(1)

        if not self.connect():
            return False

        if self.username and self.password_hash:
            data = {
                'action': 'login',
                'username': self.username,
                'password': self.password_hash
            }

            response = self.send_request(data)
            if response and response.get('status') == 'success':
                if 'encryption_key' in response:
                    encryption_key = response['encryption_key']
                    try:
                        self.fernet = Fernet(encryption_key.encode())
                        self.aes_key = encryption_key.encode()[:32]
                        if len(self.aes_key) < 32:
                            self.aes_key = self.aes_key.ljust(32, b'0')
                    except Exception as e:
                        print(f"Ошибка создания ключа при переподключении: {e}")
                self.start_receiving()
                return True
        return False

    def send_message(self, receiver, message):
        if not self.connected:
            return {'status': 'error', 'message': 'Нет подключения'}

        data = {
            'action': 'send_message',
            'sender': self.username,
            'receiver': receiver,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }

        response = self.send_request(data, timeout=10)
        if response is None:
            return {'status': 'error', 'message': 'Ошибка отправки'}
        return response

    def get_messages(self, other_user):
        data = {
            'action': 'get_messages',
            'user1': self.username,
            'user2': other_user
        }

        response = self.send_request(data)
        return response

    def search_users(self, query):
        data = {
            'action': 'search_users',
            'query': query
        }

        response = self.send_request(data)
        return response

    def send_file(self, receiver, file_path):
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 50 * 1024 * 1024:
                return {'status': 'error', 'message': 'Файл слишком большой (максимум 50 МБ)'}

            with open(file_path, 'rb') as f:
                file_data = f.read()

            if self.aes_key:
                key = self.aes_key[:32]
                if len(key) != 32:
                    key = key.ljust(32, b'0')

                cipher = AES.new(key, AES.MODE_CBC)
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
                'timestamp': datetime.now().isoformat(),
                'file_size': file_size
            }

            return self.send_request(data, timeout=30)
        except Exception as e:
            print(f"Ошибка отправки файла: {e}")
            return None

    def start_voice_call(self, receiver):
        data = {
            'action': 'start_voice_call',
            'caller': self.username,
            'receiver': receiver
        }

        return self.send_request(data)

    def update_profile(self, avatar_data=None, password=None):
        data = {
            'action': 'update_profile',
            'username': self.username,
            'avatar': avatar_data
        }

        if password:
            data['password'] = hashlib.sha256(password.encode()).hexdigest()

        return self.send_request(data)

    def get_user_avatar(self, username):
        data = {
            'action': 'get_user_avatar',
            'username': username
        }

        return self.send_request(data)

    def get_online_users(self):
        data = {
            'action': 'get_online_users'
        }

        return self.send_request(data)


class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.network_client = NetworkClient()
        self.translator = Translator()
        self.init_ui()
        self.load_saved_credentials()
        self.load_settings()

    def init_ui(self):
        self.setWindowTitle(self.translator.tr('login_title'))
        self.setFixedSize(400, 300)

        layout = QVBoxLayout()

        title = QLabel(self.translator.tr('app_title'))
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.connect_label = QLabel(self.translator.tr('connect_label'))
        self.connect_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.connect_label)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText(self.translator.tr('username_placeholder'))
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText(self.translator.tr('password_placeholder'))
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.remember_check = QCheckBox(self.translator.tr('remember_me'))
        layout.addWidget(self.remember_check)

        self.login_btn = QPushButton(self.translator.tr('login_btn'))
        self.login_btn.clicked.connect(self.login)
        layout.addWidget(self.login_btn)

        self.register_btn = QPushButton(self.translator.tr('register_btn'))
        self.register_btn.clicked.connect(self.open_register)
        layout.addWidget(self.register_btn)

        self.retry_btn = QPushButton(self.translator.tr('retry_btn'))
        self.retry_btn.clicked.connect(self.connect_to_server)
        self.retry_btn.hide()
        layout.addWidget(self.retry_btn)

        self.setLayout(layout)
        self.connect_to_server()

    def load_settings(self):
        try:
            if os.path.exists('settings.dat'):
                with open('settings.dat', 'rb') as f:
                    settings = pickle.load(f)
                    language = settings.get('language', 'ru')
                    self.translator = Translator(language)
        except:
            pass

    def load_saved_credentials(self):
        try:
            if os.path.exists('credentials.dat'):
                with open('credentials.dat', 'rb') as f:
                    data = pickle.load(f)
                    if 'username' in data:
                        self.username_input.setText(data['username'])
                    if 'password' in data and 'remember' in data and data['remember']:
                        self.password_input.setText(data['password'])
                        self.remember_check.setChecked(True)
        except:
            pass

    def save_credentials(self):
        try:
            data = {
                'username': self.username_input.text(),
                'password': self.password_input.text() if self.remember_check.isChecked() else '',
                'remember': self.remember_check.isChecked()
            }
            with open('credentials.dat', 'wb') as f:
                pickle.dump(data, f)
        except:
            pass

    def connect_to_server(self):
        self.connect_label.setText(self.translator.tr('connect_label'))
        self.login_btn.setEnabled(False)
        self.register_btn.setEnabled(False)
        self.retry_btn.hide()
        QApplication.processEvents()

        if self.network_client.connect():
            self.connect_label.setText(self.translator.tr('connected'))
            self.connect_label.setStyleSheet("color: green")
            self.login_btn.setEnabled(True)
            self.register_btn.setEnabled(True)
        else:
            self.connect_label.setText(self.translator.tr('disconnected'))
            self.connect_label.setStyleSheet("color: red")
            self.retry_btn.show()

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()

        if not username:
            QMessageBox.warning(self, "Ошибка", self.translator.tr('username_error'))
            return

        if not password:
            QMessageBox.warning(self, "Ошибка", self.translator.tr('password_error'))
            return

        if not self.network_client.connected:
            QMessageBox.warning(self, "Ошибка", self.translator.tr('connection_error'))
            return

        self.login_btn.setEnabled(False)
        self.login_btn.setText(self.translator.tr('logging_in'))
        QApplication.processEvents()

        success, message = self.network_client.login(username, password)

        if success:
            self.save_credentials()
            time.sleep(0.5)
            self.network_client.start_receiving()
            self.main_window = MainWindow(self.network_client, self.translator)
            self.main_window.show()
            self.close()
        else:
            QMessageBox.warning(self, "Ошибка", message)
            self.login_btn.setEnabled(True)
            self.login_btn.setText(self.translator.tr('login_btn'))

    def open_register(self):
        if not self.network_client.connected:
            QMessageBox.warning(self, "Ошибка", self.translator.tr('connection_error'))
            return

        self.register_window = RegisterWindow(self.network_client, self, self.translator)
        self.register_window.show()


class RegisterWindow(QWidget):
    def __init__(self, network_client, login_window, translator):
        super().__init__()
        self.network_client = network_client
        self.login_window = login_window
        self.translator = translator
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle(self.translator.tr('register_title'))
        self.setFixedSize(400, 400)

        layout = QVBoxLayout()

        title = QLabel(self.translator.tr('register_title'))
        title.setFont(QFont("Arial", 16))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText(self.translator.tr('username_min'))
        layout.addWidget(self.username_input)

        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Email")
        layout.addWidget(self.email_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText(self.translator.tr('password_min'))
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.confirm_password = QLineEdit()
        self.confirm_password.setPlaceholderText(self.translator.tr('confirm_password'))
        self.confirm_password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.confirm_password)

        self.register_btn = QPushButton(self.translator.tr('register_btn'))
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
            self.status_label.setText(self.translator.tr('username_min'))
            self.status_label.setStyleSheet("color: red")
            return

        if len(password) < 6:
            self.status_label.setText(self.translator.tr('password_min'))
            self.status_label.setStyleSheet("color: red")
            return

        if password != confirm:
            self.status_label.setText(self.translator.tr('passwords_match'))
            self.status_label.setStyleSheet("color: red")
            return

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            self.status_label.setText(self.translator.tr('email_error'))
            self.status_label.setStyleSheet("color: red")
            return

        if not self.network_client.connected:
            self.status_label.setText(self.translator.tr('connection_error'))
            self.status_label.setStyleSheet("color: red")
            return

        self.register_btn.setEnabled(False)
        self.register_btn.setText(self.translator.tr('registration'))
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
            self.register_btn.setText(self.translator.tr('register_btn'))

    def open_main_window(self):
        self.login_window.close()
        self.close()
        time.sleep(0.5)
        self.network_client.start_receiving()
        self.main_window = MainWindow(self.network_client, self.translator)
        self.main_window.show()


class ContactItem(QWidget):
    def __init__(self, username, avatar_pixmap=None, online=False, translator=None):
        super().__init__()
        self.username = username
        self.translator = translator or Translator()

        layout = QHBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)

        self.avatar_label = QLabel()
        self.update_avatar(avatar_pixmap)
        self.avatar_label.setFixedSize(40, 40)
        layout.addWidget(self.avatar_label)

        name_label = QLabel(username)
        name_label.setFont(QFont("Arial", 10))
        layout.addWidget(name_label)

        if online:
            self.status_label = QLabel(self.translator.tr('online'))
            self.status_label.setStyleSheet("color: green; font-size: 14px;")
            layout.addWidget(self.status_label)
        else:
            self.status_label = None

        layout.addStretch()
        self.setLayout(layout)

    def update_avatar(self, pixmap):
        if pixmap and not pixmap.isNull():
            scaled_pixmap = pixmap.scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.avatar_label.setPixmap(scaled_pixmap)
        else:
            pixmap = QPixmap(40, 40)
            pixmap.fill(Qt.transparent)
            painter = QPainter(pixmap)
            painter.setBrush(QBrush(QColor(100, 150, 200)))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(5, 5, 30, 30)
            painter.end()
            self.avatar_label.setPixmap(pixmap)


class MainWindow(QMainWindow):
    def __init__(self, network_client, translator):
        super().__init__()
        self.network_client = network_client
        self.translator = translator
        self.username = network_client.username
        self.current_chat = None
        self.contacts = {}
        self.avatar_cache = {}
        self.notes_messages = []
        self.admin_messages = []

        self.init_ui()

        self.network_client.message_callback = self.handle_push_message

        self.load_contacts()
        self.load_my_avatar()
        self.load_notes()
        self.load_admin_messages()

        self.add_admin_chat()

        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_connection_status)
        self.status_timer.start(3000)

        self.online_timer = QTimer()
        self.online_timer.timeout.connect(self.update_online_status)
        self.online_timer.start(30000)

        self.update_online_status()

    def init_ui(self):
        self.setWindowTitle(self.translator.tr('main_title', username=self.username))
        self.setGeometry(100, 100, 1200, 700)

        self.apply_theme()

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout()
        central_widget.setLayout(main_layout)

        left_panel = self.create_left_panel()
        main_layout.addWidget(left_panel)

        self.chat_widget = self.create_chat_panel()
        main_layout.addWidget(self.chat_widget)

        self.create_menu()

    def apply_theme(self):
        try:
            if os.path.exists('settings.dat'):
                with open('settings.dat', 'rb') as f:
                    settings = pickle.load(f)
                    theme = settings.get('theme', 'light')
            else:
                theme = 'light'

            if theme == 'dark':
                dark_palette = QPalette()
                dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
                dark_palette.setColor(QPalette.WindowText, Qt.white)
                dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
                dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
                dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
                dark_palette.setColor(QPalette.ToolTipText, Qt.white)
                dark_palette.setColor(QPalette.Text, Qt.white)
                dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
                dark_palette.setColor(QPalette.ButtonText, Qt.white)
                dark_palette.setColor(QPalette.BrightText, Qt.red)
                dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
                dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
                dark_palette.setColor(QPalette.HighlightedText, Qt.black)

                qApp.setPalette(dark_palette)
                qApp.setStyleSheet("""
                    QWidget { color: #ffffff; }
                    QLabel { color: #ffffff; }
                    QLineEdit { 
                        background-color: #2d2d2d; 
                        color: #ffffff;
                        border: 1px solid #555;
                    }
                    QTextEdit { 
                        background-color: #2d2d2d; 
                        color: #ffffff;
                        border: 1px solid #555;
                    }
                    QListWidget {
                        background-color: #2d2d2d;
                        color: #ffffff;
                        border: 1px solid #555;
                    }
                    QPushButton {
                        background-color: #3d3d3d;
                        color: #ffffff;
                        border: 1px solid #555;
                        padding: 5px;
                    }
                    QPushButton:hover {
                        background-color: #4d4d4d;
                    }
                    QMenuBar {
                        background-color: #3d3d3d;
                        color: #ffffff;
                    }
                    QMenuBar::item:selected {
                        background-color: #2a82da;
                    }
                    QMenu {
                        background-color: #3d3d3d;
                        color: #ffffff;
                        border: 1px solid #555;
                    }
                    QMenu::item:selected {
                        background-color: #2a82da;
                    }
                    QDialog {
                        background-color: #353535;
                    }
                """)
            else:
                qApp.setPalette(qApp.style().standardPalette())
                qApp.setStyleSheet("")
        except Exception as e:
            print(f"Ошибка темы: {e}")

    def create_left_panel(self):
        left_panel = QWidget()
        left_panel.setMaximumWidth(350)
        left_layout = QVBoxLayout()

        top_widget = QWidget()
        top_layout = QVBoxLayout()

        avatar_layout = QHBoxLayout()

        self.avatar_btn = QPushButton()
        self.avatar_btn.setFixedSize(60, 60)
        self.avatar_btn.setStyleSheet("""
            QPushButton {
                border-radius: 30px;
                border: none;
                background-color: transparent;
            }
            QPushButton:hover {
                background-color: rgba(0,0,0,0.1);
            }
        """)
        self.avatar_btn.clicked.connect(self.open_profile_settings)
        avatar_layout.addWidget(self.avatar_btn)

        avatar_layout.addStretch()
        top_layout.addLayout(avatar_layout)

        self.username_label = QLabel(self.username)
        self.username_label.setAlignment(Qt.AlignCenter)
        self.username_label.setFont(QFont("Arial", 12, QFont.Bold))
        top_layout.addWidget(self.username_label)

        search_btn = QPushButton(self.translator.tr('search_users'))
        search_btn.clicked.connect(self.search_users)
        top_layout.addWidget(search_btn)

        top_widget.setLayout(top_layout)
        left_layout.addWidget(top_widget)

        left_layout.addWidget(QLabel(self.translator.tr('chats')))

        self.chat_list = QListWidget()
        self.chat_list.itemClicked.connect(self.open_chat)
        self.chat_list.setIconSize(QSize(40, 40))
        left_layout.addWidget(self.chat_list)

        status_widget = QWidget()
        status_layout = QHBoxLayout()

        self.status_label = QLabel(self.translator.tr('connection_ok'))
        self.status_label.setStyleSheet("color: green")
        status_layout.addWidget(self.status_label)

        self.reconnect_btn = QPushButton("⟳")
        self.reconnect_btn.setFixedSize(25, 25)
        self.reconnect_btn.setToolTip(self.translator.tr('reconnect'))
        self.reconnect_btn.clicked.connect(self.reconnect_to_server)
        self.reconnect_btn.hide()
        status_layout.addWidget(self.reconnect_btn)

        status_widget.setLayout(status_layout)
        left_layout.addWidget(status_widget)

        left_panel.setLayout(left_layout)
        return left_panel

    def create_chat_panel(self):
        chat_widget = QWidget()
        self.chat_layout = QVBoxLayout()

        header_widget = QWidget()
        header_layout = QHBoxLayout()

        self.chat_header = QLabel(self.translator.tr('select_chat'))
        self.chat_header.setFont(QFont("Arial", 14, QFont.Bold))
        header_layout.addWidget(self.chat_header)

        self.call_btn = QPushButton("📞")
        self.call_btn.setFixedSize(40, 40)
        self.call_btn.setToolTip(self.translator.tr('start_call'))
        self.call_btn.clicked.connect(self.start_voice_call)
        self.call_btn.setEnabled(False)
        header_layout.addWidget(self.call_btn)

        self.file_btn = QPushButton("📎")
        self.file_btn.setFixedSize(40, 40)
        self.file_btn.setToolTip(self.translator.tr('send_file'))
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
        self.message_input.setPlaceholderText(self.translator.tr('message_placeholder'))
        self.message_input.returnPressed.connect(self.send_message)
        input_layout.addWidget(self.message_input)

        self.send_btn = QPushButton(self.translator.tr('send_btn'))
        self.send_btn.clicked.connect(self.send_message)
        input_layout.addWidget(self.send_btn)

        input_widget.setLayout(input_layout)
        self.chat_layout.addWidget(input_widget)

        chat_widget.setLayout(self.chat_layout)
        return chat_widget

    def create_menu(self):
        menubar = self.menuBar()

        settings_menu = menubar.addMenu(self.translator.tr('settings'))

        theme_action = QAction(self.translator.tr('theme'), self)
        theme_action.triggered.connect(self.change_theme)
        settings_menu.addAction(theme_action)

        language_menu = settings_menu.addMenu('Язык / Language')

        ru_action = QAction('Русский', self)
        ru_action.triggered.connect(lambda: self.change_language('ru'))
        language_menu.addAction(ru_action)

        en_action = QAction('English', self)
        en_action.triggered.connect(lambda: self.change_language('en'))
        language_menu.addAction(en_action)

        reconnect_action = QAction(self.translator.tr('reconnect'), self)
        reconnect_action.triggered.connect(self.reconnect_to_server)
        settings_menu.addAction(reconnect_action)

        settings_menu.addSeparator()

        logout_action = QAction(self.translator.tr('logout'), self)
        logout_action.triggered.connect(self.logout)
        settings_menu.addAction(logout_action)

        tools_menu = menubar.addMenu(self.translator.tr('tools'))
        refresh_action = QAction(self.translator.tr('refresh_contacts'), self)
        refresh_action.triggered.connect(self.load_contacts)
        tools_menu.addAction(refresh_action)

    def change_language(self, language):
        try:
            if os.path.exists('settings.dat'):
                with open('settings.dat', 'rb') as f:
                    settings = pickle.load(f)
            else:
                settings = {}

            settings['language'] = language

            with open('settings.dat', 'wb') as f:
                pickle.dump(settings, f)

            QMessageBox.information(self, "Язык",
                                    f"Язык изменен. Перезапустите приложение для применения изменений.")
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось изменить язык: {str(e)}")

    def reconnect_to_server(self):
        self.status_label.setText("Переподключение...")
        self.reconnect_btn.hide()
        QApplication.processEvents()

        if self.network_client.reconnect_and_login():
            self.status_label.setText(self.translator.tr('connection_ok'))
            self.status_label.setStyleSheet("color: green")
            self.reconnect_btn.hide()
        else:
            self.status_label.setText(self.translator.tr('connection_lost'))
            self.status_label.setStyleSheet("color: red")
            self.reconnect_btn.show()

    def update_connection_status(self):
        if not self.network_client.connected:
            self.status_label.setText(self.translator.tr('connection_lost'))
            self.status_label.setStyleSheet("color: red")
            self.reconnect_btn.show()
        else:
            self.status_label.setText(self.translator.tr('connection_ok'))
            self.status_label.setStyleSheet("color: green")
            self.reconnect_btn.hide()

    def logout(self):
        reply = QMessageBox.question(self, self.translator.tr('logout'),
                                     self.translator.tr('logout_confirm'),
                                     QMessageBox.Yes | QMessageBox.No)

        if reply == QMessageBox.Yes:
            self.network_client.disconnect()
            self.save_notes()
            self.save_admin_messages()

            self.login_window = LoginWindow()
            self.login_window.show()
            self.close()

    def change_theme(self):
        try:
            if os.path.exists('settings.dat'):
                with open('settings.dat', 'rb') as f:
                    settings = pickle.load(f)
            else:
                settings = {}

            current_theme = settings.get('theme', 'light')
            new_theme = 'dark' if current_theme == 'light' else 'light'

            settings['theme'] = new_theme

            with open('settings.dat', 'wb') as f:
                pickle.dump(settings, f)

            self.apply_theme()

            QMessageBox.information(self, self.translator.tr('theme_changed'),
                                    f"Тема изменена на: {'Темную' if new_theme == 'dark' else 'Светлую'}")
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось изменить тему: {str(e)}")

    def load_contacts(self):
        self.chat_list.clear()
        self.contacts = {}

        self.add_special_chats()

        try:
            if os.path.exists(f"{self.username}_contacts.json"):
                with open(f"{self.username}_contacts.json", 'r') as f:
                    contact_list = json.load(f)

                    for contact in contact_list:
                        self.add_contact_to_list(contact)
        except:
            pass

    def add_special_chats(self):
        admin_item = QListWidgetItem(self.chat_list)
        admin_item.setText(self.translator.tr('administration'))
        admin_item.setData(Qt.UserRole, "Администрация")

        notes_item = QListWidgetItem(self.chat_list)
        notes_item.setText(self.translator.tr('notes'))
        notes_item.setData(Qt.UserRole, "Заметки")

    def add_admin_chat(self):
        self.contacts["Администрация"] = {
            'widget': None,
            'item': None,
            'avatar': None
        }

    def add_contact_to_list(self, username):
        if username in self.contacts:
            return

        avatar_pixmap = self.get_cached_avatar(username)
        contact_widget = ContactItem(username, avatar_pixmap, False, self.translator)

        item = QListWidgetItem()
        item.setSizeHint(contact_widget.sizeHint())
        item.setText(username)
        item.setData(Qt.UserRole, username)

        self.chat_list.addItem(item)
        self.chat_list.setItemWidget(item, contact_widget)

        self.contacts[username] = {
            'widget': contact_widget,
            'item': item,
            'avatar': avatar_pixmap,
            'is_online': False
        }

    def get_cached_avatar(self, username):
        if username in self.avatar_cache:
            return self.avatar_cache[username]

        if username == "Администрация":
            pixmap = QPixmap(40, 40)
            pixmap.fill(Qt.transparent)
            painter = QPainter(pixmap)
            painter.setBrush(QBrush(QColor(220, 20, 60)))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(5, 5, 30, 30)
            painter.end()
            self.avatar_cache[username] = pixmap
            return pixmap

        if username == "Заметки":
            pixmap = QPixmap(40, 40)
            pixmap.fill(Qt.transparent)
            painter = QPainter(pixmap)
            painter.setBrush(QBrush(QColor(50, 205, 50)))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(5, 5, 30, 30)
            painter.end()
            self.avatar_cache[username] = pixmap
            return pixmap

        response = self.network_client.get_user_avatar(username)
        if response and response.get('status') == 'success' and response.get('avatar'):
            try:
                avatar_bytes = base64.b64decode(response['avatar'])
                pixmap = QPixmap()
                if pixmap.loadFromData(avatar_bytes):
                    self.avatar_cache[username] = pixmap
                    return pixmap
            except Exception as e:
                print(f"Ошибка загрузки аватара для {username}: {e}")

        pixmap = QPixmap(40, 40)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setBrush(QBrush(QColor(100, 150, 200)))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(5, 5, 30, 30)
        painter.end()
        self.avatar_cache[username] = pixmap
        return pixmap

    def load_my_avatar(self):
        response = self.network_client.get_user_avatar(self.username)
        if response and response.get('status') == 'success' and response.get('avatar'):
            try:
                avatar_bytes = base64.b64decode(response['avatar'])
                pixmap = QPixmap()
                if pixmap.loadFromData(avatar_bytes):
                    pixmap = pixmap.scaled(60, 60, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    icon = QIcon(pixmap)
                    self.avatar_btn.setIcon(icon)
                    self.avatar_btn.setIconSize(QSize(60, 60))
            except Exception as e:
                print(f"Ошибка загрузки моего аватара: {e}")
                self.set_default_avatar_btn()
        else:
            self.set_default_avatar_btn()

    def set_default_avatar_btn(self):
        pixmap = QPixmap(60, 60)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setBrush(QBrush(QColor(100, 150, 200)))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(5, 5, 50, 50)
        painter.end()
        self.avatar_btn.setIcon(QIcon(pixmap))
        self.avatar_btn.setIconSize(QSize(60, 60))

    def update_online_status(self):
        if not self.network_client.connected:
            return

        response = self.network_client.get_online_users()
        if response and response.get('status') == 'success':
            online_users = response.get('users', [])

            for username, contact_data in self.contacts.items():
                if username not in ["Администрация", "Заметки"]:
                    is_online = username in online_users
                    contact_data['is_online'] = is_online

    def open_profile_settings(self):
        dialog = ProfileSettingsDialog(self.network_client, self.username, self, self.translator)
        if dialog.exec_():
            self.load_my_avatar()
            if self.username in self.avatar_cache:
                del self.avatar_cache[self.username]

    def search_users(self):
        dialog = SearchDialog(self.network_client, self, self.translator)
        if dialog.exec_():
            selected_user = dialog.get_selected_user()
            if selected_user:
                self.add_contact(selected_user)

    def add_contact(self, username):
        if username == self.username:
            QMessageBox.warning(self, "Ошибка", self.translator.tr('cant_add_self'))
            return

        if username in self.contacts:
            QMessageBox.information(self, "Информация", self.translator.tr('already_contact'))
            return

        try:
            if os.path.exists(f"{self.username}_contacts.json"):
                with open(f"{self.username}_contacts.json", 'r') as f:
                    contact_list = json.load(f)
            else:
                contact_list = []

            if username not in contact_list:
                contact_list.append(username)
                with open(f"{self.username}_contacts.json", 'w') as f:
                    json.dump(contact_list, f)
        except:
            pass

        self.add_contact_to_list(username)

    def open_chat(self, item):
        chat_type = item.data(Qt.UserRole)

        if chat_type == "Администрация":
            self.open_admin_chat()
        elif chat_type == "Заметки":
            self.open_notes()
        else:
            self.open_chat_with_user(chat_type)

    def open_admin_chat(self):
        self.current_chat = "Администрация"
        self.chat_header.setText(self.translator.tr('administration'))
        self.messages_area.clear()
        self.call_btn.setEnabled(False)
        self.file_btn.setEnabled(False)

        for msg in self.admin_messages:
            self.messages_area.append(msg)

        scrollbar = self.messages_area.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def open_notes(self):
        self.current_chat = "Заметки"
        self.chat_header.setText(self.translator.tr('notes'))
        self.messages_area.clear()
        self.call_btn.setEnabled(False)
        self.file_btn.setEnabled(False)

        for note in self.notes_messages:
            self.messages_area.append(note)

        scrollbar = self.messages_area.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def open_chat_with_user(self, user):
        self.current_chat = user
        self.chat_header.setText(self.translator.tr('chat_with', user=user))
        self.messages_area.clear()

        response = self.network_client.get_messages(user)
        if response and response.get('status') == 'success':
            messages = response.get('messages', [])
            for msg in messages:
                self.display_message(msg)

        self.call_btn.setEnabled(True)
        self.file_btn.setEnabled(True)

        scrollbar = self.messages_area.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def display_message(self, msg):
        sender = msg.get('sender')
        text = msg.get('message')
        timestamp = msg.get('timestamp', '')[:19].replace('T', ' ')

        if sender == self.username:
            self.messages_area.append(f"[{timestamp}] <b>Вы:</b> {text}")
        else:
            self.messages_area.append(f"[{timestamp}] <b>{sender}:</b> {text}")

    def send_message(self):
        if not self.current_chat:
            return

        message = self.message_input.text().strip()
        if not message:
            return

        if self.current_chat == "Заметки":
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
            note = f"[{timestamp}] {message}"
            self.notes_messages.append(note)
            self.messages_area.append(note)
            self.message_input.clear()
            self.save_notes()

        elif self.current_chat == "Администрация":
            self.message_input.clear()

        elif self.current_chat:
            response = self.network_client.send_message(self.current_chat, message)
            if response and response.get('status') == 'success':
                timestamp = datetime.now().strftime("%H:%M")
                self.messages_area.append(f"[{timestamp}] <b>Вы:</b> {message}")
                self.message_input.clear()

                scrollbar = self.messages_area.verticalScrollBar()
                scrollbar.setValue(scrollbar.maximum())
            else:
                QMessageBox.warning(self, "Ошибка", self.translator.tr('message_error'))

    def send_file(self):
        if not self.current_chat or self.current_chat in ["Администрация", "Заметки"]:
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self, self.translator.tr('send_file'), "", "Все файлы (*)"
        )

        if file_path:
            response = self.network_client.send_file(self.current_chat, file_path)
            if response and response.get('status') == 'success':
                timestamp = datetime.now().strftime("%H:%M")
                file_name = os.path.basename(file_path)
                self.messages_area.append(f"[{timestamp}] <b>Вы отправили файл:</b> {file_name}")

                scrollbar = self.messages_area.verticalScrollBar()
                scrollbar.setValue(scrollbar.maximum())
            else:
                QMessageBox.warning(self, "Ошибка", self.translator.tr('file_error'))

    def start_voice_call(self):
        if not self.current_chat or self.current_chat in ["Администрация", "Заметки"]:
            return

        response = self.network_client.start_voice_call(self.current_chat)
        if response and response.get('status') == 'success':
            QMessageBox.information(self, "Звонок", self.translator.tr('call_started'))
        else:
            QMessageBox.warning(self, "Ошибка", self.translator.tr('call_error'))

    def handle_push_message(self, message):
        action = message.get('action')

        if action == 'new_message':
            sender = message.get('sender')
            text = message.get('message')
            timestamp = message.get('timestamp', '')[:19].replace('T', ' ')

            if self.current_chat == sender:
                self.messages_area.append(f"[{timestamp}] <b>{sender}:</b> {text}")
                scrollbar = self.messages_area.verticalScrollBar()
                scrollbar.setValue(scrollbar.maximum())

            QApplication.alert(self)

        elif action == 'new_file':
            sender = message.get('sender')
            file_name = message.get('file_name')
            timestamp = message.get('timestamp', '')[:19].replace('T', ' ')

            if self.current_chat == sender:
                self.messages_area.append(f"[{timestamp}] <b>{sender} отправил файл:</b> {file_name}")
                scrollbar = self.messages_area.verticalScrollBar()
                scrollbar.setValue(scrollbar.maximum())

            QApplication.alert(self)

        elif action == 'voice_call':
            caller = message.get('caller')
            reply = QMessageBox.question(
                self, "Входящий звонок",
                f"Пользователь {caller} звонит вам. Принять звонок?",
                QMessageBox.Yes | QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                QMessageBox.information(self, "Звонок", "Звонок принят")

        elif action == 'broadcast':
            subject = message.get('subject', self.translator.tr('broadcast_notification'))
            text = message.get('message', '')
            timestamp = message.get('timestamp', '')[:19].replace('T', ' ')

            admin_msg = f"[{timestamp}] <b>{subject}:</b> {text}"
            self.admin_messages.append(admin_msg)
            self.save_admin_messages()

            if self.current_chat == "Администрация":
                self.messages_area.append(admin_msg)
                scrollbar = self.messages_area.verticalScrollBar()
                scrollbar.setValue(scrollbar.maximum())

            QApplication.alert(self)
            QMessageBox.information(self, subject, text)

    def load_notes(self):
        try:
            if os.path.exists(f"{self.username}_notes.json"):
                with open(f"{self.username}_notes.json", 'r', encoding='utf-8') as f:
                    self.notes_messages = json.load(f)
        except:
            self.notes_messages = []

    def save_notes(self):
        try:
            with open(f"{self.username}_notes.json", 'w', encoding='utf-8') as f:
                json.dump(self.notes_messages, f, ensure_ascii=False, indent=2)
        except:
            pass

    def load_admin_messages(self):
        try:
            if os.path.exists(f"{self.username}_admin.json"):
                with open(f"{self.username}_admin.json", 'r', encoding='utf-8') as f:
                    self.admin_messages = json.load(f)
        except:
            self.admin_messages = []

    def save_admin_messages(self):
        try:
            with open(f"{self.username}_admin.json", 'w', encoding='utf-8') as f:
                json.dump(self.admin_messages, f, ensure_ascii=False, indent=2)
        except:
            pass


class ProfileSettingsDialog(QDialog):
    def __init__(self, network_client, username, main_window, translator):
        super().__init__()
        self.network_client = network_client
        self.username = username
        self.main_window = main_window
        self.translator = translator
        self.avatar_data = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle(self.translator.tr('profile_settings'))
        self.setFixedSize(400, 450)

        layout = QVBoxLayout()

        avatar_layout = QHBoxLayout()
        self.avatar_label = QLabel()
        response = self.network_client.get_user_avatar(self.username)
        if response and response.get('status') == 'success' and response.get('avatar'):
            try:
                avatar_bytes = base64.b64decode(response['avatar'])
                pixmap = QPixmap()
                if pixmap.loadFromData(avatar_bytes):
                    pixmap = pixmap.scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    self.avatar_label.setPixmap(pixmap)
            except:
                self.set_default_avatar()
        else:
            self.set_default_avatar()
        avatar_layout.addWidget(self.avatar_label)

        self.change_avatar_btn = QPushButton(self.translator.tr('change_avatar'))
        self.change_avatar_btn.clicked.connect(self.change_avatar)
        avatar_layout.addWidget(self.change_avatar_btn)

        layout.addLayout(avatar_layout)

        layout.addWidget(QLabel("Имя пользователя:"))
        self.username_edit = QLineEdit(self.username)
        self.username_edit.setReadOnly(True)
        layout.addWidget(self.username_edit)

        layout.addWidget(QLabel(self.translator.tr('new_password')))
        self.new_password = QLineEdit()
        self.new_password.setEchoMode(QLineEdit.Password)
        self.new_password.setPlaceholderText("Оставьте пустым, если не хотите менять")
        layout.addWidget(self.new_password)

        layout.addWidget(QLabel(self.translator.tr('confirm_password')))
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

    def set_default_avatar(self):
        pixmap = QPixmap(100, 100)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setBrush(QBrush(QColor(100, 150, 200)))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(10, 10, 80, 80)
        painter.end()
        self.avatar_label.setPixmap(pixmap)

    def change_avatar(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self, self.translator.tr('change_avatar'), "", "Images (*.png *.jpg *.jpeg *.bmp)"
        )
        if file_name:
            try:
                with open(file_name, 'rb') as f:
                    self.avatar_data = base64.b64encode(f.read()).decode()

                pixmap = QPixmap(file_name).scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                self.avatar_label.setPixmap(pixmap)
            except Exception as e:
                QMessageBox.warning(self, "Ошибка", f"Не удалось загрузить аватар: {e}")

    def save_changes(self):
        new_password = self.new_password.text()
        confirm = self.confirm_password.text()

        if new_password and new_password != confirm:
            QMessageBox.warning(self, "Ошибка", self.translator.tr('passwords_match'))
            return

        response = self.network_client.update_profile(
            avatar_data=self.avatar_data,
            password=new_password if new_password else None
        )

        if response and response.get('status') == 'success':
            QMessageBox.information(self, "Успех", self.translator.tr('profile_updated'))
            self.accept()
        else:
            error_msg = response.get('message', 'Неизвестная ошибка') if response else 'Ошибка соединения'
            QMessageBox.warning(self, "Ошибка", f"{self.translator.tr('profile_error')}: {error_msg}")


class SearchResultItem(QWidget):
    def __init__(self, username, avatar_pixmap=None, translator=None):
        super().__init__()
        self.username = username
        self.translator = translator or Translator()

        layout = QHBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)

        self.avatar_label = QLabel()
        if avatar_pixmap and not avatar_pixmap.isNull():
            scaled_pixmap = avatar_pixmap.scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.avatar_label.setPixmap(scaled_pixmap)
        else:
            pixmap = QPixmap(40, 40)
            pixmap.fill(Qt.transparent)
            painter = QPainter(pixmap)
            painter.setBrush(QBrush(QColor(100, 150, 200)))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(5, 5, 30, 30)
            painter.end()
            self.avatar_label.setPixmap(pixmap)
        self.avatar_label.setFixedSize(40, 40)
        layout.addWidget(self.avatar_label)

        name_label = QLabel(username)
        name_label.setFont(QFont("Arial", 10))
        layout.addWidget(name_label)

        layout.addStretch()
        self.setLayout(layout)


class SearchDialog(QDialog):
    def __init__(self, network_client, main_window, translator):
        super().__init__()
        self.network_client = network_client
        self.main_window = main_window
        self.translator = translator
        self.selected_user = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle(self.translator.tr('search_users'))
        self.setFixedSize(400, 400)

        layout = QVBoxLayout()

        layout.addWidget(QLabel("Поиск по имени пользователя:"))

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(self.translator.tr('search_placeholder'))
        layout.addWidget(self.search_input)

        self.search_btn = QPushButton(self.translator.tr('search_btn'))
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
        query = self.search_input.text().strip()
        if not query:
            QMessageBox.warning(self, "Ошибка", "Введите запрос для поиска")
            return

        self.results_list.clear()

        if not self.network_client.connected:
            QMessageBox.warning(self, "Ошибка", self.translator.tr('search_error'))
            return

        response = self.network_client.search_users(query)

        if response and response.get('status') == 'success':
            users = response.get('users', [])
            if users:
                for user in users:
                    username = user['username']
                    if username != self.main_window.username:
                        avatar_response = self.network_client.get_user_avatar(username)
                        avatar_pixmap = None

                        if avatar_response and avatar_response.get('status') == 'success' and avatar_response.get(
                                'avatar'):
                            try:
                                avatar_bytes = base64.b64decode(avatar_response['avatar'])
                                pixmap = QPixmap()
                                if pixmap.loadFromData(avatar_bytes):
                                    avatar_pixmap = pixmap
                            except:
                                pass

                        item_widget = SearchResultItem(username, avatar_pixmap, self.translator)
                        item = QListWidgetItem(self.results_list)
                        item.setSizeHint(item_widget.sizeHint())
                        item.setText(username)

                        self.results_list.addItem(item)
                        self.results_list.setItemWidget(item, item_widget)
            else:
                QMessageBox.information(self, "Результат", self.translator.tr('no_users'))
        else:
            error_msg = response.get('message', 'Ошибка сервера') if response else 'Ошибка соединения'
            QMessageBox.warning(self, "Ошибка", f"Не удалось выполнить поиск: {error_msg}")

    def select_user(self, item):
        self.selected_user = item.text()

    def get_selected_user(self):
        return self.selected_user


if __name__ == "__main__":
    app = QApplication(sys.argv)

    language = 'ru'
    try:
        if os.path.exists('settings.dat'):
            with open('settings.dat', 'rb') as f:
                settings = pickle.load(f)
                language = settings.get('language', 'ru')
    except:
        pass

    translator = Translator(language)
    login_window = LoginWindow()
    login_window.translator = translator
    login_window.setWindowTitle(translator.tr('login_title'))
    login_window.show()

    sys.exit(app.exec_())