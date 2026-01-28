import sys
import socket
import threading
import json
import sqlite3
import base64
import hashlib
import os
import time
from datetime import datetime
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from cryptography.fernet import Fernet
import hashlib
import pickle


class SecureServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.clients = {}
        self.lock = threading.Lock()
        self.heartbeat_interval = 30

        self.init_database()

    def init_database(self):
        self.conn = sqlite3.connect('secure_messenger.db', check_same_thread=False)
        self.cursor = self.conn.cursor()

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                avatar TEXT,
                registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                encryption_key TEXT NOT NULL
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                delivered INTEGER DEFAULT 0
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_data TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                delivered INTEGER DEFAULT 0
            )
        ''')

        self.conn.commit()
        print("База данных готова")

    def generate_encryption_key(self):
        key = Fernet.generate_key()
        return key.decode('utf-8')

    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            self.server_socket.settimeout(1)
            self.running = True

            print(f"Сервер запущен на {self.host}:{self.port}")

            accept_thread = threading.Thread(target=self.accept_connections, daemon=True)
            accept_thread.start()

            return True
        except Exception as e:
            print(f"Ошибка запуска сервера: {e}")
            return False

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()

        with self.lock:
            for username, client_data in list(self.clients.items()):
                try:
                    client_data['socket'].close()
                except:
                    pass
            self.clients.clear()

        print("Сервер остановлен")

    def accept_connections(self):
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                client_socket.settimeout(30)
                print(f"Новое подключение от {address}")

                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"Ошибка принятия соединения: {e}")
                break

    def _recv_exact(self, sock, n):
        data = b''
        while len(data) < n:
            try:
                chunk = sock.recv(min(8192, n - len(data)))
                if not chunk:
                    return None
                data += chunk
            except socket.timeout:
                continue
            except:
                return None
        return data

    def _send_all(self, sock, data):
        try:
            sock.sendall(data)
            return True
        except:
            return False

    def handle_client(self, client_socket, address):
        username = None

        try:
            while self.running:
                try:
                    length_data = self._recv_exact(client_socket, 4)
                    if not length_data:
                        break

                    message_length = int.from_bytes(length_data, 'big')

                    if message_length <= 0 or message_length > 50 * 1024 * 1024:
                        print(f"Некорректная длина сообщения от {address}")
                        break

                    data = self._recv_exact(client_socket, message_length)
                    if not data:
                        break

                    try:
                        request = json.loads(data.decode('utf-8'))
                    except json.JSONDecodeError as e:
                        print(f"Ошибка декодирования JSON от {address}: {e}")
                        error_response = json.dumps({
                            'status': 'error',
                            'message': 'Неверный формат запроса'
                        }).encode()
                        if not self._send_all(client_socket, len(error_response).to_bytes(4, 'big')):
                            break
                        if not self._send_all(client_socket, error_response):
                            break
                        continue

                    if request.get('action') == 'ping':
                        response = {'status': 'success', 'message': 'pong'}
                        response_data = json.dumps(response).encode('utf-8')
                        if not self._send_all(client_socket, len(response_data).to_bytes(4, 'big')):
                            break
                        if not self._send_all(client_socket, response_data):
                            break
                        continue

                    response = self.process_request(request, username)

                    if request.get('action') in ['register', 'login'] and response.get('status') == 'success':
                        username = request.get('username')
                        if 'encryption_key' in response:
                            try:
                                client_fernet = Fernet(response['encryption_key'].encode('utf-8'))
                                with self.lock:
                                    self.clients[username] = {
                                        'socket': client_socket,
                                        'fernet': client_fernet,
                                        'address': address,
                                        'last_active': datetime.now()
                                    }
                                print(f"Пользователь {username} добавлен в онлайн список")
                            except Exception as e:
                                print(f"Ошибка создания fernet для {username}: {e}")

                    response_data = json.dumps(response).encode('utf-8')
                    if not self._send_all(client_socket, len(response_data).to_bytes(4, 'big')):
                        break
                    if not self._send_all(client_socket, response_data):
                        break

                except Exception as e:
                    print(f"Ошибка обработки запроса от {address}: {e}")
                    break

        except Exception as e:
            print(f"Критическая ошибка обработки клиента {address}: {e}")
        finally:
            if username:
                with self.lock:
                    if username in self.clients:
                        del self.clients[username]
                        print(f"Пользователь {username} удален из онлайн списка")
            try:
                client_socket.close()
            except:
                pass
            print(f"Клиент {address} отключен")

    def process_request(self, request, username):
        action = request.get('action')

        try:
            if action == 'register':
                return self.handle_register(request)
            elif action == 'login':
                return self.handle_login(request)
            elif action == 'send_message':
                return self.handle_send_message(request, username)
            elif action == 'send_file':
                return self.handle_send_file(request, username)
            elif action == 'start_voice_call':
                return self.handle_start_voice_call(request)
            elif action == 'get_messages':
                return self.handle_get_messages(request)
            elif action == 'search_users':
                return self.handle_search_users(request)
            elif action == 'update_profile':
                return self.handle_update_profile(request)
            elif action == 'get_user_avatar':
                return self.handle_get_user_avatar(request)
            elif action == 'get_online_users':
                return self.handle_get_online_users()
            else:
                return {'status': 'error', 'message': 'Неизвестное действие'}
        except Exception as e:
            print(f"Ошибка обработки действия {action}: {e}")
            return {'status': 'error', 'message': 'Ошибка сервера'}

    def handle_register(self, request):
        try:
            username = request.get('username', '').strip()
            email = request.get('email', '').strip().lower()
            password_hash = request.get('password')

            print(f"Попытка регистрации: username={username}, email={email}")

            if not username or not email or not password_hash:
                return {'status': 'error', 'message': 'Все поля обязательны'}

            if len(username) < 3:
                return {'status': 'error', 'message': 'Имя должно быть не менее 3 символов'}

            if '@' not in email or '.' not in email:
                return {'status': 'error', 'message': 'Некорректный email'}

            self.cursor.execute(
                "SELECT username, email FROM users WHERE username = ? OR email = ?",
                (username, email)
            )
            existing = self.cursor.fetchone()

            if existing:
                existing_username, existing_email = existing
                if existing_username == username:
                    return {'status': 'error', 'message': 'Имя пользователя уже занято'}
                elif existing_email == email:
                    return {'status': 'error', 'message': 'Email уже зарегистрирован'}

            encryption_key = self.generate_encryption_key()

            self.cursor.execute(
                "INSERT INTO users (username, email, password_hash, encryption_key) VALUES (?, ?, ?, ?)",
                (username, email, password_hash, encryption_key)
            )
            self.conn.commit()

            print(f"Пользователь {username} успешно зарегистрирован")

            return {
                'status': 'success',
                'message': 'Регистрация успешна',
                'encryption_key': encryption_key
            }

        except sqlite3.IntegrityError as e:
            error_str = str(e)
            if "UNIQUE constraint failed: users.username" in error_str:
                return {'status': 'error', 'message': 'Имя пользователя уже занято'}
            elif "UNIQUE constraint failed: users.email" in error_str:
                return {'status': 'error', 'message': 'Email уже зарегистрирован'}
            else:
                return {'status': 'error', 'message': 'Ошибка базы данных'}
        except Exception as e:
            print(f"Неожиданная ошибка при регистрации: {e}")
            return {'status': 'error', 'message': 'Ошибка сервера'}

    def handle_login(self, request):
        username = request.get('username')
        password_hash = request.get('password')

        self.cursor.execute(
            "SELECT password_hash, encryption_key FROM users WHERE username = ?",
            (username,)
        )
        result = self.cursor.fetchone()

        if not result:
            return {'status': 'error', 'message': 'Пользователь не найден'}

        stored_hash, encryption_key = result

        if password_hash != stored_hash:
            return {'status': 'error', 'message': 'Неверный пароль'}

        self.cursor.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ?",
            (username,)
        )
        self.conn.commit()

        print(f"Пользователь {username} успешно вошел")

        return {
            'status': 'success',
            'message': 'Вход выполнен',
            'encryption_key': encryption_key
        }

    def handle_send_message(self, request, sender):
        if not sender:
            return {'status': 'error', 'message': 'Не авторизован'}

        receiver = request.get('receiver')
        message = request.get('message')
        timestamp = request.get('timestamp')

        self.cursor.execute("SELECT username FROM users WHERE username = ?", (receiver,))
        if not self.cursor.fetchone():
            return {'status': 'error', 'message': 'Получатель не найден'}

        self.cursor.execute(
            "INSERT INTO messages (sender, receiver, message, timestamp) VALUES (?, ?, ?, ?)",
            (sender, receiver, message, timestamp)
        )
        self.conn.commit()

        with self.lock:
            if receiver in self.clients:
                try:
                    receiver_data = self.clients[receiver]
                    notification = {
                        'type': 'push',
                        'action': 'new_message',
                        'sender': sender,
                        'message': message,
                        'timestamp': timestamp
                    }

                    response_data = json.dumps(notification).encode('utf-8')
                    receiver_socket = receiver_data['socket']
                    if not self._send_all(receiver_socket, len(response_data).to_bytes(4, 'big')):
                        return {'status': 'error', 'message': 'Ошибка отправки уведомления'}
                    if not self._send_all(receiver_socket, response_data):
                        return {'status': 'error', 'message': 'Ошибка отправки уведомления'}

                    self.cursor.execute(
                        "UPDATE messages SET delivered = 1 WHERE sender = ? AND receiver = ? AND timestamp = ?",
                        (sender, receiver, timestamp)
                    )
                    self.conn.commit()
                    print(f"Сообщение от {sender} доставлено {receiver}")
                except Exception as e:
                    print(f"Ошибка отправки уведомления: {e}")

        return {'status': 'success', 'message': 'Сообщение отправлено'}

    def handle_send_file(self, request, sender):
        if not sender:
            return {'status': 'error', 'message': 'Не авторизован'}

        receiver = request.get('receiver')
        file_name = request.get('file_name')
        file_data = request.get('file_data')
        timestamp = request.get('timestamp')
        file_size = request.get('file_size', 0)

        if file_size > 50 * 1024 * 1024:
            return {'status': 'error', 'message': 'Файл слишком большой (максимум 50 МБ)'}

        self.cursor.execute("SELECT username FROM users WHERE username = ?", (receiver,))
        if not self.cursor.fetchone():
            return {'status': 'error', 'message': 'Получатель не найден'}

        self.cursor.execute(
            "INSERT INTO files (sender, receiver, file_name, file_data, timestamp) VALUES (?, ?, ?, ?, ?)",
            (sender, receiver, file_name, file_data, timestamp)
        )
        self.conn.commit()

        with self.lock:
            if receiver in self.clients:
                try:
                    receiver_data = self.clients[receiver]
                    notification = {
                        'type': 'push',
                        'action': 'new_file',
                        'sender': sender,
                        'file_name': file_name,
                        'timestamp': timestamp
                    }

                    response_data = json.dumps(notification).encode('utf-8')
                    receiver_socket = receiver_data['socket']
                    if not self._send_all(receiver_socket, len(response_data).to_bytes(4, 'big')):
                        return {'status': 'error', 'message': 'Ошибка отправки уведомления'}
                    if not self._send_all(receiver_socket, response_data):
                        return {'status': 'error', 'message': 'Ошибка отправки уведомления'}

                    print(f"Уведомление о файле от {sender} отправлено {receiver}")
                except Exception as e:
                    print(f"Ошибка отправки уведомления о файле: {e}")

        return {'status': 'success', 'message': 'Файл отправлен'}

    def handle_start_voice_call(self, request):
        caller = request.get('caller')
        receiver = request.get('receiver')

        with self.lock:
            if receiver in self.clients:
                try:
                    receiver_data = self.clients[receiver]
                    notification = {
                        'type': 'push',
                        'action': 'voice_call',
                        'caller': caller,
                        'timestamp': datetime.now().isoformat()
                    }

                    response_data = json.dumps(notification).encode('utf-8')
                    receiver_socket = receiver_data['socket']
                    if not self._send_all(receiver_socket, len(response_data).to_bytes(4, 'big')):
                        return {'status': 'error', 'message': 'Ошибка отправки уведомления'}
                    if not self._send_all(receiver_socket, response_data):
                        return {'status': 'error', 'message': 'Ошибка отправки уведомления'}
                except Exception as e:
                    print(f"Ошибка отправки уведомления о звонке: {e}")
                    return {'status': 'error', 'message': 'Ошибка отправки уведомления'}

                return {'status': 'success', 'message': 'Получатель доступен'}
            else:
                return {'status': 'error', 'message': 'Получатель не в сети'}

    def handle_get_messages(self, request):
        user1 = request.get('user1')
        user2 = request.get('user2')

        self.cursor.execute(
            """
            SELECT sender, message, timestamp 
            FROM messages 
            WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
            ORDER BY timestamp ASC
            LIMIT 100
            """,
            (user1, user2, user2, user1)
        )

        messages = []
        for row in self.cursor.fetchall():
            messages.append({
                'sender': row[0],
                'message': row[1],
                'timestamp': row[2]
            })

        return {'status': 'success', 'messages': messages}

    def handle_search_users(self, request):
        query = request.get('query', '')

        if not query:
            self.cursor.execute("SELECT username FROM users LIMIT 50")
        else:
            self.cursor.execute(
                "SELECT username FROM users WHERE username LIKE ? LIMIT 50",
                (f"%{query}%",)
            )

        users = []
        for row in self.cursor.fetchall():
            users.append({
                'username': row[0]
            })

        return {'status': 'success', 'users': users}

    def handle_update_profile(self, request):
        username = request.get('username')
        avatar = request.get('avatar')
        password = request.get('password')

        try:
            updates = []
            params = []

            if avatar:
                updates.append("avatar = ?")
                params.append(avatar)

            if password:
                updates.append("password_hash = ?")
                params.append(password)

            if not updates:
                return {'status': 'error', 'message': 'Нет изменений для обновления'}

            params.append(username)
            query = f"UPDATE users SET {', '.join(updates)} WHERE username = ?"

            self.cursor.execute(query, params)
            self.conn.commit()

            print(f"Профиль пользователя {username} обновлен")
            return {'status': 'success', 'message': 'Профиль обновлен'}
        except Exception as e:
            print(f"Ошибка обновления профиля: {e}")
            return {'status': 'error', 'message': 'Ошибка обновления профиля'}

    def handle_get_user_avatar(self, request):
        username = request.get('username')

        self.cursor.execute(
            "SELECT avatar FROM users WHERE username = ?",
            (username,)
        )
        result = self.cursor.fetchone()

        if result and result[0]:
            return {'status': 'success', 'avatar': result[0]}
        else:
            return {'status': 'success', 'avatar': None}

    def handle_get_online_users(self):
        with self.lock:
            online_users = list(self.clients.keys())
        return {'status': 'success', 'users': online_users}

    def send_broadcast(self, subject, message):
        broadcast_data = {
            'type': 'push',
            'action': 'broadcast',
            'subject': subject,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }

        response_data = json.dumps(broadcast_data).encode('utf-8')

        with self.lock:
            count = len(self.clients)
            failed = 0
            for username, client_data in self.clients.items():
                try:
                    if not self._send_all(client_data['socket'], len(response_data).to_bytes(4, 'big')):
                        failed += 1
                        continue
                    if not self._send_all(client_data['socket'], response_data):
                        failed += 1
                        continue
                except Exception as e:
                    print(f"Ошибка отправки рассылки пользователю {username}: {e}")
                    failed += 1

        return count - failed


class UserEditDialog(QDialog):
    def __init__(self, username, cursor, conn, parent=None):
        super().__init__(parent)
        self.username = username
        self.cursor = cursor
        self.conn = conn
        self.avatar_data = None
        self.setWindowTitle(f"Редактирование пользователя: {username}")
        self.setFixedSize(400, 500)
        self.init_ui()
        self.load_user_data()

    def init_ui(self):
        layout = QVBoxLayout()

        avatar_layout = QHBoxLayout()
        self.avatar_label = QLabel()
        self.avatar_label.setFixedSize(100, 100)
        avatar_layout.addWidget(self.avatar_label)

        self.change_avatar_btn = QPushButton("Сменить аватар")
        self.change_avatar_btn.clicked.connect(self.change_avatar)
        avatar_layout.addWidget(self.change_avatar_btn)

        layout.addLayout(avatar_layout)

        layout.addWidget(QLabel("Имя пользователя:"))
        self.username_edit = QLineEdit()
        layout.addWidget(self.username_edit)

        layout.addWidget(QLabel("Email:"))
        self.email_edit = QLineEdit()
        layout.addWidget(self.email_edit)

        layout.addWidget(QLabel("Новый пароль (оставьте пустым, если не меняете):"))
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_edit)

        layout.addWidget(QLabel("Подтвердите пароль:"))
        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.confirm_password_edit)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self.save_changes)
        buttons.rejected.connect(self.reject)

        layout.addWidget(buttons)
        self.setLayout(layout)

    def load_user_data(self):
        self.cursor.execute(
            "SELECT username, email, avatar FROM users WHERE username = ?",
            (self.username,)
        )
        result = self.cursor.fetchone()

        if result:
            self.username_edit.setText(result[0])
            self.email_edit.setText(result[1])

            if result[2]:
                try:
                    avatar_bytes = base64.b64decode(result[2])
                    pixmap = QPixmap()
                    if pixmap.loadFromData(avatar_bytes):
                        pixmap = pixmap.scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                        self.avatar_label.setPixmap(pixmap)
                        self.avatar_data = result[2]
                except:
                    self.set_default_avatar()
            else:
                self.set_default_avatar()

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
            self, "Выберите аватар", "", "Images (*.png *.jpg *.jpeg *.bmp)"
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
        new_username = self.username_edit.text().strip()
        new_email = self.email_edit.text().strip().lower()
        password = self.password_edit.text()
        confirm_password = self.confirm_password_edit.text()

        if not new_username or not new_email:
            QMessageBox.warning(self, "Ошибка", "Имя пользователя и email не могут быть пустыми")
            return

        if password and password != confirm_password:
            QMessageBox.warning(self, "Ошибка", "Пароли не совпадают")
            return

        try:
            if new_username != self.username:
                self.cursor.execute(
                    "SELECT username FROM users WHERE username = ?",
                    (new_username,)
                )
                if self.cursor.fetchone():
                    QMessageBox.warning(self, "Ошибка", "Имя пользователя уже занято")
                    return

            if new_email != self.email_edit.text():
                self.cursor.execute(
                    "SELECT email FROM users WHERE email = ? AND username != ?",
                    (new_email, self.username)
                )
                if self.cursor.fetchone():
                    QMessageBox.warning(self, "Ошибка", "Email уже зарегистрирован")
                    return

            updates = []
            params = []

            if new_username != self.username:
                updates.append("username = ?")
                params.append(new_username)

            updates.append("email = ?")
            params.append(new_email)

            if self.avatar_data:
                updates.append("avatar = ?")
                params.append(self.avatar_data)

            if password:
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                updates.append("password_hash = ?")
                params.append(password_hash)

            params.append(self.username)

            query = f"UPDATE users SET {', '.join(updates)} WHERE username = ?"
            self.cursor.execute(query, params)
            self.conn.commit()

            QMessageBox.information(self, "Успех", "Данные пользователя обновлены")
            self.accept()

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось обновить данные: {e}")


class ServerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.server = SecureServer()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Secure Messenger Server")
        self.setGeometry(200, 200, 1000, 700)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()

        server_panel = self.create_server_panel()
        layout.addWidget(server_panel)

        self.tabs = QTabWidget()

        self.users_tab = QWidget()
        self.init_users_tab()
        self.tabs.addTab(self.users_tab, "Пользователи")

        self.stats_tab = QWidget()
        self.init_stats_tab()
        self.tabs.addTab(self.stats_tab, "Статистика")

        self.broadcast_tab = QWidget()
        self.init_broadcast_tab()
        self.tabs.addTab(self.broadcast_tab, "Рассылка")

        self.logs_tab = QWidget()
        self.init_logs_tab()
        self.tabs.addTab(self.logs_tab, "Логи")

        layout.addWidget(self.tabs)
        central_widget.setLayout(layout)

        self.create_menu()

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(3000)

    def create_server_panel(self):
        panel = QWidget()
        layout = QHBoxLayout()

        self.start_btn = QPushButton("Запустить сервер")
        self.start_btn.clicked.connect(self.start_server)
        layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Остановить сервер")
        self.stop_btn.clicked.connect(self.stop_server)
        self.stop_btn.setEnabled(False)
        layout.addWidget(self.stop_btn)

        self.status_label = QLabel("Сервер остановлен")
        self.status_label.setStyleSheet("color: red; font-weight: bold;")
        layout.addWidget(self.status_label)

        layout.addStretch()

        self.clients_label = QLabel("Подключено: 0")
        layout.addWidget(self.clients_label)

        self.port_label = QLabel("Порт: 5555")
        layout.addWidget(self.port_label)

        panel.setLayout(layout)
        return panel

    def init_users_tab(self):
        layout = QVBoxLayout()

        search_panel = QWidget()
        search_layout = QHBoxLayout()

        search_layout.addWidget(QLabel("Поиск:"))
        self.user_search_input = QLineEdit()
        self.user_search_input.setPlaceholderText("Имя пользователя или email")
        search_layout.addWidget(self.user_search_input)

        self.search_btn = QPushButton("Найти")
        self.search_btn.clicked.connect(self.search_users)
        search_layout.addWidget(self.search_btn)

        search_panel.setLayout(search_layout)
        layout.addWidget(search_panel)

        self.users_table = QTableWidget()
        self.users_table.setColumnCount(7)
        self.users_table.setHorizontalHeaderLabels([
            "ID", "Имя", "Email", "Регистрация", "Последний вход", "Аватар", "Действия"
        ])
        self.users_table.horizontalHeader().setStretchLastSection(True)
        self.users_table.itemDoubleClicked.connect(self.on_user_double_clicked)
        layout.addWidget(self.users_table)

        button_panel = QWidget()
        button_layout = QHBoxLayout()

        self.refresh_btn = QPushButton("Обновить")
        self.refresh_btn.clicked.connect(self.load_users)
        button_layout.addWidget(self.refresh_btn)

        self.delete_btn = QPushButton("Удалить выбранных")
        self.delete_btn.clicked.connect(self.delete_selected_users)
        button_layout.addWidget(self.delete_btn)

        button_panel.setLayout(button_layout)
        layout.addWidget(button_panel)

        self.users_tab.setLayout(layout)
        self.load_users()

    def init_stats_tab(self):
        layout = QVBoxLayout()

        stats_group = QGroupBox("Статистика сервера")
        stats_layout = QVBoxLayout()

        self.total_users_label = QLabel("Всего пользователей: 0")
        stats_layout.addWidget(self.total_users_label)

        self.online_users_label = QLabel("Онлайн пользователей: 0")
        stats_layout.addWidget(self.online_users_label)

        self.total_messages_label = QLabel("Всего сообщений: 0")
        stats_layout.addWidget(self.total_messages_label)

        self.total_files_label = QLabel("Всего файлов: 0")
        stats_layout.addWidget(self.total_files_label)

        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)

        self.stats_tab.setLayout(layout)

    def init_broadcast_tab(self):
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Рассылка сообщений:"))

        self.broadcast_subject = QLineEdit()
        self.broadcast_subject.setPlaceholderText("Тема сообщения")
        layout.addWidget(self.broadcast_subject)

        self.broadcast_message = QTextEdit()
        self.broadcast_message.setPlaceholderText("Текст сообщения...")
        layout.addWidget(self.broadcast_message)

        self.broadcast_btn = QPushButton("Отправить всем пользователям")
        self.broadcast_btn.clicked.connect(self.send_broadcast)
        layout.addWidget(self.broadcast_btn)

        layout.addStretch()
        self.broadcast_tab.setLayout(layout)

    def init_logs_tab(self):
        layout = QVBoxLayout()

        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        layout.addWidget(self.logs_text)

        button_panel = QWidget()
        button_layout = QHBoxLayout()

        self.clear_logs_btn = QPushButton("Очистить логи")
        self.clear_logs_btn.clicked.connect(self.clear_logs)
        button_layout.addWidget(self.clear_logs_btn)

        self.save_logs_btn = QPushButton("Сохранить логи")
        self.save_logs_btn.clicked.connect(self.save_logs)
        button_layout.addWidget(self.save_logs_btn)

        button_panel.setLayout(button_layout)
        layout.addWidget(button_panel)

        self.logs_tab.setLayout(layout)

    def create_menu(self):
        menubar = self.menuBar()

        server_menu = menubar.addMenu('Сервер')

        start_action = QAction('Запустить', self)
        start_action.triggered.connect(self.start_server)
        server_menu.addAction(start_action)

        stop_action = QAction('Остановить', self)
        stop_action.triggered.connect(self.stop_server)
        server_menu.addAction(stop_action)

        server_menu.addSeparator()

        exit_action = QAction('Выход', self)
        exit_action.triggered.connect(self.close)
        server_menu.addAction(exit_action)

    def start_server(self):
        if self.server.start():
            self.status_label.setText("✓ Сервер запущен")
            self.status_label.setStyleSheet("color: green; font-weight: bold;")
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.log("Сервер запущен на порту 5555")
        else:
            QMessageBox.critical(self, "Ошибка", "Не удалось запустить сервер")

    def stop_server(self):
        self.server.stop()
        self.status_label.setText("Сервер остановлен")
        self.status_label.setStyleSheet("color: red; font-weight: bold;")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.log("Сервер остановлен")

    def load_users(self):
        try:
            self.server.cursor.execute(
                "SELECT id, username, email, registration_date, last_login, avatar FROM users ORDER BY id"
            )
            users = self.server.cursor.fetchall()

            self.users_table.setRowCount(len(users))

            for row, user in enumerate(users):
                for col in range(5):
                    value = user[col] if user[col] else ""
                    self.users_table.setItem(row, col, QTableWidgetItem(str(value)))

                avatar_item = QTableWidgetItem()
                if user[5]:
                    try:
                        avatar_bytes = base64.b64decode(user[5])
                        pixmap = QPixmap()
                        if pixmap.loadFromData(avatar_bytes):
                            pixmap = pixmap.scaled(32, 32, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                            avatar_item.setIcon(QIcon(pixmap))
                    except:
                        self.set_default_avatar_icon(avatar_item)
                else:
                    self.set_default_avatar_icon(avatar_item)
                self.users_table.setItem(row, 5, avatar_item)

                actions_widget = QWidget()
                actions_layout = QHBoxLayout()
                actions_layout.setContentsMargins(0, 0, 0, 0)

                edit_btn = QPushButton("Редактировать")
                edit_btn.clicked.connect(lambda checked, u=user[1]: self.edit_user(u))
                actions_layout.addWidget(edit_btn)

                delete_btn = QPushButton("Удалить")
                delete_btn.clicked.connect(lambda checked, u=user[1]: self.delete_user(u))
                actions_layout.addWidget(delete_btn)

                actions_widget.setLayout(actions_layout)
                self.users_table.setCellWidget(row, 6, actions_widget)

                for col in range(6):
                    item = self.users_table.item(row, col)
                    if item:
                        item.setTextAlignment(Qt.AlignCenter)
        except Exception as e:
            self.log(f"Ошибка загрузки пользователей: {e}")

    def set_default_avatar_icon(self, avatar_item):
        pixmap = QPixmap(32, 32)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setBrush(QBrush(QColor(100, 150, 200)))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(1, 1, 30, 30)
        painter.end()
        avatar_item.setIcon(QIcon(pixmap))

    def on_user_double_clicked(self, item):
        row = item.row()
        username = self.users_table.item(row, 1).text()
        self.edit_user(username)

    def edit_user(self, username):
        dialog = UserEditDialog(username, self.server.cursor, self.server.conn, self)
        if dialog.exec_():
            self.load_users()

    def search_users(self):
        query = self.user_search_input.text()
        try:
            if query:
                self.server.cursor.execute(
                    "SELECT id, username, email, registration_date, last_login, avatar FROM users WHERE username LIKE ? OR email LIKE ?",
                    (f"%{query}%", f"%{query}%")
                )
            else:
                self.server.cursor.execute(
                    "SELECT id, username, email, registration_date, last_login, avatar FROM users ORDER BY id"
                )

            users = self.server.cursor.fetchall()

            self.users_table.setRowCount(len(users))

            for row, user in enumerate(users):
                for col in range(5):
                    value = user[col] if user[col] else ""
                    self.users_table.setItem(row, col, QTableWidgetItem(str(value)))

                avatar_item = QTableWidgetItem()
                if user[5]:
                    try:
                        avatar_bytes = base64.b64decode(user[5])
                        pixmap = QPixmap()
                        if pixmap.loadFromData(avatar_bytes):
                            pixmap = pixmap.scaled(32, 32, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                            avatar_item.setIcon(QIcon(pixmap))
                    except:
                        self.set_default_avatar_icon(avatar_item)
                else:
                    self.set_default_avatar_icon(avatar_item)
                self.users_table.setItem(row, 5, avatar_item)

                actions_widget = QWidget()
                actions_layout = QHBoxLayout()
                actions_layout.setContentsMargins(0, 0, 0, 0)

                edit_btn = QPushButton("Редактировать")
                edit_btn.clicked.connect(lambda checked, u=user[1]: self.edit_user(u))
                actions_layout.addWidget(edit_btn)

                delete_btn = QPushButton("Удалить")
                delete_btn.clicked.connect(lambda checked, u=user[1]: self.delete_user(u))
                actions_layout.addWidget(delete_btn)

                actions_widget.setLayout(actions_layout)
                self.users_table.setCellWidget(row, 6, actions_widget)

                for col in range(6):
                    item = self.users_table.item(row, col)
                    if item:
                        item.setTextAlignment(Qt.AlignCenter)
        except Exception as e:
            self.log(f"Ошибка поиска пользователей: {e}")

    def delete_user(self, username):
        reply = QMessageBox.question(
            self, 'Подтверждение',
            f'Удалить пользователя {username}?',
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            try:
                self.server.cursor.execute("DELETE FROM users WHERE username = ?", (username,))
                self.server.conn.commit()

                with self.server.lock:
                    if username in self.server.clients:
                        try:
                            self.server.clients[username]['socket'].close()
                        except:
                            pass
                        del self.server.clients[username]

                self.load_users()
                self.log(f"Пользователь {username} удален")
            except Exception as e:
                self.log(f"Ошибка удаления пользователя: {e}")

    def delete_selected_users(self):
        selected = self.users_table.selectionModel().selectedRows()
        if selected:
            reply = QMessageBox.question(
                self, 'Подтверждение',
                f'Удалить выбранных пользователей ({len(selected)} шт.)?',
                QMessageBox.Yes | QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                for index in selected:
                    username = self.users_table.item(index.row(), 1).text()
                    self.delete_user(username)

    def send_broadcast(self):
        subject = self.broadcast_subject.text()
        message = self.broadcast_message.toPlainText()

        if not subject or not message:
            QMessageBox.warning(self, "Ошибка", "Заполните тему и сообщение")
            return

        sent_count = self.server.send_broadcast(subject, message)

        QMessageBox.information(
            self, "Рассылка",
            f"Сообщение отправлено {sent_count} пользователям"
        )
        self.broadcast_subject.clear()
        self.broadcast_message.clear()
        self.log(f"Рассылка отправлена: {subject} ({sent_count} пользователей)")

    def update_stats(self):
        try:
            self.server.cursor.execute("SELECT COUNT(*) FROM users")
            total_users = self.server.cursor.fetchone()[0]
            self.total_users_label.setText(f"Всего пользователей: {total_users}")

            with self.server.lock:
                online_users = len(self.server.clients)
                self.online_users_label.setText(f"Онлайн пользователей: {online_users}")
                self.clients_label.setText(f"Подключено: {online_users}")

            self.server.cursor.execute("SELECT COUNT(*) FROM messages")
            total_messages = self.server.cursor.fetchone()[0]
            self.total_messages_label.setText(f"Всего сообщений: {total_messages}")

            self.server.cursor.execute("SELECT COUNT(*) FROM files")
            total_files = self.server.cursor.fetchone()[0]
            self.total_files_label.setText(f"Всего файлов: {total_files}")

        except Exception as e:
            print(f"Ошибка обновления статистики: {e}")

    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.logs_text.append(f"[{timestamp}] {message}")

    def clear_logs(self):
        self.logs_text.clear()

    def save_logs(self):
        file_name, _ = QFileDialog.getSaveFileName(
            self, "Сохранить логи", "", "Text Files (*.txt)"
        )
        if file_name:
            try:
                with open(file_name, 'w', encoding='utf-8') as f:
                    f.write(self.logs_text.toPlainText())
                self.log(f"Логи сохранены в {file_name}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить логи: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)

    server = ServerWindow()
    server.show()
    sys.exit(app.exec_())