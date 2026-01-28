import sys
import socket
import threading
import json
import os
import base64
import time
import re
import sqlite3
from datetime import datetime
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Complete Localization with English
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
        'send_file': 'Отправить файл',
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
        'logout_confirm': 'Вы уверены, что хотите выйти из аккаунта?',
        'profile_updated': 'Профиль обновлен',
        'profile_error': 'Не удалось обновить профиль',
        'email_label': 'Email',
        'search_query_label': 'Поиск по имени пользователя:',
        'enter_query': 'Введите запрос для поиска',
        'query_too_short': 'Запрос слишком короткий (минимум 2 символа)',
        'search_failed': 'Не удалось выполнить поиск',
        'password_keep': 'Оставьте пустым, чтобы не менять',
        'file_too_large': 'Файл слишком большой (макс. 5МБ)',
        'file_sent': 'Файл отправлен успешно',
        'file_send_failed': 'Не удалось отправить файл',
        'message_send_failed': 'Не удалось отправить сообщение',
        'avatar_too_large': 'Аватар слишком большой (макс. 1МБ)',
        'avatar_load_failed': 'Не удалось загрузить аватар',
        'no_changes': 'Нет изменений для сохранения',
        'registration_success': 'Регистрация успешна! Войдите в систему.',
        'select_file': 'Выберите файл',
        'language': 'Язык / Language',
        'language_changed': 'Язык изменен. Перезапустите приложение.',
        'reconnecting': 'Переподключение...',
        'new_message': 'Новое сообщение',
        'new_message_from': 'Новое сообщение от',
        'add_to_chat': 'Добавить в чат',
        'user_added': 'Пользователь {user} добавлен в чат',
        'add_user_btn': 'Добавить',
        'close_btn': 'Закрыть',
        'offline_mode': 'Офлайн режим',
        'offline_mode_info': 'Просмотр локальных сообщений',
        'sync_messages': 'Синхронизировать с сервером',
        'sync_complete': 'Синхронизация завершена',
        'delete_for_all': 'Удалить для всех',
        'message_deleted': 'Сообщение удалено',
        'confirm_delete': 'Вы уверены, что хотите удалить это сообщение?',
        'edit_message': 'Редактировать',
        'save_edit': 'Сохранить',
        'encryption_error': 'Ошибка шифрования',
        'offline_storage': 'Локальное хранилище',
        'clear_local': 'Очистить локальные сообщения',
        'clear_local_confirm': 'Очистить все локальные сообщения?',
        'local_cleared': 'Локальные сообщения очищены',
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
        'send_file': 'Send file',
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
        'logout_confirm': 'Are you sure you want to logout?',
        'profile_updated': 'Profile updated',
        'profile_error': 'Failed to update profile',
        'email_label': 'Email',
        'search_query_label': 'Search by username:',
        'enter_query': 'Enter search query',
        'query_too_short': 'Query too short (minimum 2 characters)',
        'search_failed': 'Failed to search',
        'password_keep': 'Leave empty to keep current password',
        'file_too_large': 'File too large (max 5MB)',
        'file_sent': 'File sent successfully',
        'file_send_failed': 'Failed to send file',
        'message_send_failed': 'Failed to send message',
        'avatar_too_large': 'Avatar too large (max 1MB)',
        'avatar_load_failed': 'Failed to load avatar',
        'no_changes': 'No changes to save',
        'registration_success': 'Registration successful! Please login.',
        'select_file': 'Select File',
        'language': 'Language / Язык',
        'language_changed': 'Language changed. Restart the application.',
        'reconnecting': 'Reconnecting...',
        'new_message': 'New Message',
        'new_message_from': 'New message from',
        'add_to_chat': 'Add to chat',
        'user_added': 'User {user} added to chat list',
        'add_user_btn': 'Add',
        'close_btn': 'Close',
        'offline_mode': 'Offline Mode',
        'offline_mode_info': 'Viewing local messages',
        'sync_messages': 'Sync with server',
        'sync_complete': 'Sync completed',
        'delete_for_all': 'Delete for everyone',
        'message_deleted': 'Message deleted',
        'confirm_delete': 'Are you sure you want to delete this message?',
        'edit_message': 'Edit',
        'save_edit': 'Save',
        'encryption_error': 'Encryption error',
        'offline_storage': 'Local Storage',
        'clear_local': 'Clear local messages',
        'clear_local_confirm': 'Clear all local messages?',
        'local_cleared': 'Local messages cleared',
    }
}


class Translator:
    """Simple translation system with fallback"""

    def __init__(self, language='en'):
        self.language = language
        self.translations = TRANSLATIONS.get(language, TRANSLATIONS['en'])

    def tr(self, key, **kwargs):
        text = self.translations.get(key, key)
        if kwargs:
            try:
                text = text.format(**kwargs)
            except:
                pass
        return text


class LocalStorage:
    """Local SQLite storage for offline mode"""

    def __init__(self, username):
        self.username = username
        self.db_file = f'local_storage_{username}.db'
        self.init_database()

    def init_database(self):
        """Initialize local database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Messages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                local_id TEXT UNIQUE,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                is_encrypted INTEGER DEFAULT 0,
                is_sent INTEGER DEFAULT 1,
                is_delivered INTEGER DEFAULT 0,
                is_read INTEGER DEFAULT 0,
                is_deleted INTEGER DEFAULT 0
            )
        ''')

        # Contacts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contacts (
                username TEXT PRIMARY KEY,
                avatar BLOB,
                last_seen DATETIME,
                online_status INTEGER DEFAULT 0
            )
        ''')

        # Settings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def save_message(self, local_id, sender, receiver, message, timestamp, is_encrypted=False, is_sent=True):
        """Save message to local storage"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT OR REPLACE INTO messages 
                (local_id, sender, receiver, message, timestamp, is_encrypted, is_sent)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (local_id, sender, receiver, message, timestamp, 1 if is_encrypted else 0, 1 if is_sent else 0))

            conn.commit()
            return True
        except Exception as e:
            print(f"Error saving message: {e}")
            return False
        finally:
            conn.close()

    def get_messages(self, contact, limit=100):
        """Get messages with contact from local storage"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT sender, receiver, message, timestamp, is_encrypted
            FROM messages 
            WHERE ((sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?))
            AND is_deleted = 0
            ORDER BY timestamp ASC
            LIMIT ?
        ''', (self.username, contact, contact, self.username, limit))

        messages = []
        for row in cursor.fetchall():
            messages.append({
                'sender': row[0],
                'receiver': row[1],
                'message': row[2],
                'timestamp': row[3],
                'is_encrypted': bool(row[4])
            })

        conn.close()
        return messages

    def delete_messages(self, contact):
        """Delete messages with contact (soft delete)"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        cursor.execute('''
            UPDATE messages 
            SET is_deleted = 1 
            WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
        ''', (self.username, contact, contact, self.username))

        conn.commit()
        conn.close()

    def clear_all_messages(self):
        """Clear all messages (for logout)"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        cursor.execute('DELETE FROM messages')
        cursor.execute('DELETE FROM contacts')

        conn.commit()
        conn.close()

    def save_contact(self, username, avatar=None, online=False):
        """Save contact to local storage"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO contacts (username, avatar, last_seen, online_status)
            VALUES (?, ?, ?, ?)
        ''', (username, avatar, datetime.now().isoformat(), 1 if online else 0))

        conn.commit()
        conn.close()

    def get_contacts(self):
        """Get all contacts from local storage"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        cursor.execute('SELECT username, avatar, online_status FROM contacts')
        contacts = []
        for row in cursor.fetchall():
            contacts.append({
                'username': row[0],
                'avatar': row[1],
                'online': bool(row[2])
            })

        conn.close()
        return contacts


class NetworkClient:
    """Secure network client with encryption and local storage"""

    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.username = None
        self.password = None
        self.fernet = None
        self.local_storage = None
        self.lock = threading.Lock()
        self.message_callback = None
        self.receive_thread = None
        self.stop_receiving = False
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 5
        self.offline_mode = False
        self.pending_messages = []

    def generate_key_from_password(self, password, salt=None):
        """Generate encryption key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key), salt.hex()

    def connect(self):
        """Connect to server"""
        if self.offline_mode:
            return False

        try:
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((self.host, self.port))
            self.connected = True
            self.reconnect_attempts = 0
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            self.connected = False
            return False

    def disconnect(self):
        """Disconnect from server"""
        self.stop_receiving = True
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass

    def _send_request(self, request):
        """Send request to server"""
        try:
            data = json.dumps(request).encode('utf-8')
            length = len(data).to_bytes(4, 'big')

            with self.lock:
                self.socket.sendall(length + data)

                length_data = self._recv_exact(4)
                if not length_data:
                    self.connected = False
                    return None

                response_length = int.from_bytes(length_data, 'big')

                response_data = self._recv_exact(response_length)
                if not response_data:
                    self.connected = False
                    return None

                return json.loads(response_data.decode('utf-8'))
        except Exception as e:
            print(f"Send request error: {e}")
            self.connected = False
            return None

    def _recv_exact(self, n):
        """Receive exact number of bytes"""
        data = b''
        while len(data) < n:
            try:
                chunk = self.socket.recv(min(8192, n - len(data)))
                if not chunk:
                    return None
                data += chunk
            except socket.timeout:
                break
        return data

    def register(self, username, email, password):
        """Register new user with secure key generation"""
        request = {
            'action': 'register',
            'username': username,
            'email': email,
            'password': password
        }

        response = self._send_request(request)

        if response and response.get('status') == 'success':
            # Generate encryption key from password
            self.fernet, salt = self.generate_key_from_password(password)
            self.username = username
            self.password = password
            self.local_storage = LocalStorage(username)

            # Save salt locally
            conn = sqlite3.connect(f'local_storage_{username}.db')
            cursor = conn.cursor()
            cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)',
                           ('salt', salt))
            conn.commit()
            conn.close()

            return True, response.get('message', 'Success')
        else:
            return False, response.get('message', 'Registration failed') if response else 'Connection error'

    def login(self, username, password):
        """Login to server or use offline mode"""
        # Try to connect first
        if not self.connect():
            self.offline_mode = True
            # Try to load from local storage
            self.username = username
            self.local_storage = LocalStorage(username)

            # Try to load encryption key from saved salt
            try:
                conn = sqlite3.connect(f'local_storage_{username}.db')
                cursor = conn.cursor()
                cursor.execute('SELECT value FROM settings WHERE key = ?', ('salt',))
                result = cursor.fetchone()
                conn.close()

                if result:
                    salt = bytes.fromhex(result[0])
                    self.fernet, _ = self.generate_key_from_password(password, salt)
                    return True, "Offline mode: Using local storage"
                else:
                    # Cannot decrypt messages without salt
                    return False, "Cannot access encrypted messages in offline mode"
            except:
                return False, "Cannot access local storage"

        # Online login
        request = {
            'action': 'login',
            'username': username,
            'password': password
        }

        response = self._send_request(request)

        if response and response.get('status') == 'success':
            # Generate encryption key from password
            self.fernet, salt = self.generate_key_from_password(password)
            self.username = username
            self.password = password
            self.local_storage = LocalStorage(username)
            self.offline_mode = False

            # Save salt locally
            conn = sqlite3.connect(f'local_storage_{username}.db')
            cursor = conn.cursor()
            cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)',
                           ('salt', salt))
            conn.commit()
            conn.close()

            return True, response.get('message', 'Success')
        else:
            return False, response.get('message', 'Login failed') if response else 'Connection error'

    def send_message(self, receiver, message):
        """Send encrypted message"""
        try:
            # Generate local ID for the message
            local_id = f"{self.username}_{receiver}_{int(time.time() * 1000)}"
            timestamp = datetime.now().isoformat()

            # Save to local storage first
            if self.local_storage:
                self.local_storage.save_message(
                    local_id, self.username, receiver, message, timestamp,
                    is_encrypted=False, is_sent=False
                )

            # If in offline mode, queue message
            if self.offline_mode or not self.connected:
                self.pending_messages.append({
                    'receiver': receiver,
                    'message': message,
                    'local_id': local_id
                })
                return True

            # Encrypt message for transmission
            if self.fernet:
                encrypted_message = self.fernet.encrypt(message.encode('utf-8')).decode('utf-8')
            else:
                encrypted_message = message

            request = {
                'action': 'send_message',
                'receiver': receiver,
                'message': encrypted_message,
                'local_id': local_id
            }

            response = self._send_request(request)

            if response and response.get('status') == 'success':
                # Mark as sent in local storage
                if self.local_storage:
                    self.update_message_status(local_id, is_sent=True)
                return True
            else:
                return False
        except Exception as e:
            print(f"Send message error: {e}")
            return False

    def update_message_status(self, local_id, is_sent=True, is_delivered=False):
        """Update message status in local storage"""
        if not self.local_storage:
            return False

        conn = sqlite3.connect(f'local_storage_{self.username}.db')
        cursor = conn.cursor()

        if is_delivered:
            cursor.execute('UPDATE messages SET is_delivered = 1 WHERE local_id = ?', (local_id,))
        elif is_sent:
            cursor.execute('UPDATE messages SET is_sent = 1 WHERE local_id = ?', (local_id,))

        conn.commit()
        conn.close()
        return True

    def get_messages(self, contact, use_local=False):
        """Get messages with contact - FIXED: now properly decrypts messages"""
        if use_local or self.offline_mode or not self.connected:
            # Get messages from local storage
            if self.local_storage:
                messages = self.local_storage.get_messages(contact)
                # Decrypt messages if we have the key
                for msg in messages:
                    if msg.get('is_encrypted') and self.fernet:
                        try:
                            msg['message'] = self.fernet.decrypt(msg['message'].encode('utf-8')).decode('utf-8')
                        except:
                            pass
                return messages
            return []

        # Get messages from server
        request = {
            'action': 'get_messages',
            'contact': contact
        }

        response = self._send_request(request)

        if response and response.get('status') == 'success':
            messages = response.get('messages', [])
            for msg in messages:
                # Store in local storage
                if self.local_storage:
                    self.local_storage.save_message(
                        msg.get('local_id', ''),
                        msg['sender'],
                        msg['receiver'],
                        msg['message'],
                        msg.get('timestamp', datetime.now().isoformat()),
                        is_encrypted=True
                    )

                # Decrypt message
                try:
                    if self.fernet and msg.get('message'):
                        msg['message'] = self.fernet.decrypt(msg['message'].encode('utf-8')).decode('utf-8')
                except Exception as e:
                    print(f"Decryption error: {e}")
                    msg['message'] = "[Encryption Error]"

            return messages
        return []

    def sync_pending_messages(self):
        """Sync pending messages when connection is restored"""
        if not self.connected or self.offline_mode:
            return False

        successful = []
        for msg in self.pending_messages[:]:  # Copy list for iteration
            if self.send_message(msg['receiver'], msg['message']):
                successful.append(msg)
                self.pending_messages.remove(msg)

        return len(successful) > 0

    def send_file(self, receiver, file_path):
        """Send file"""
        try:
            with open(file_path, 'rb') as f:
                file_data = base64.b64encode(f.read()).decode('utf-8')

            file_name = os.path.basename(file_path)

            request = {
                'action': 'send_file',
                'receiver': receiver,
                'file_name': file_name,
                'file_data': file_data
            }

            response = self._send_request(request)
            return response and response.get('status') == 'success'
        except Exception as e:
            print(f"Send file error: {e}")
            return False

    def get_contacts(self):
        """Get list of contacts"""
        if self.offline_mode or not self.connected:
            if self.local_storage:
                return self.local_storage.get_contacts()
            return []

        request = {'action': 'get_contacts'}
        response = self._send_request(request)

        if response and response.get('status') == 'success':
            contacts = response.get('contacts', [])
            # Save to local storage
            if self.local_storage:
                for contact in contacts:
                    self.local_storage.save_contact(
                        contact['username'],
                        online=contact.get('online', False)
                    )
            return contacts
        return []

    def search_users(self, query):
        """Search users"""
        if self.offline_mode or not self.connected:
            return {'status': 'error', 'message': 'Cannot search in offline mode'}

        request = {
            'action': 'search_users',
            'query': query
        }
        return self._send_request(request)

    def update_profile(self, avatar_data=None, password=None):
        """Update user profile"""
        if not avatar_data and not password:
            return {'status': 'error', 'message': 'No changes to save'}

        request = {
            'action': 'update_profile'
        }

        if avatar_data:
            request['avatar_data'] = avatar_data

        if password:
            request['password'] = password

        return self._send_request(request)

    def get_user_avatar(self, username):
        """Get user avatar"""
        request = {
            'action': 'get_user_avatar',
            'username': username
        }
        return self._send_request(request)

    def delete_message(self, message_id, for_all=False):
        """Delete message from server"""
        if self.offline_mode or not self.connected:
            return {'status': 'error', 'message': 'Cannot delete in offline mode'}

        request = {
            'action': 'delete_message',
            'message_id': message_id,
            'for_all': for_all
        }
        return self._send_request(request)

    def start_receiving(self):
        """Start receiving messages in background"""
        if self.offline_mode:
            return False

        self.stop_receiving = False
        self.receive_thread = threading.Thread(target=self._receive_messages, daemon=True)
        self.receive_thread.start()
        return True

    def _receive_messages(self):
        """Receive messages in background"""
        while not self.stop_receiving and self.connected:
            try:
                length_data = self._recv_exact(4)
                if not length_data:
                    self.connected = False
                    break

                message_length = int.from_bytes(length_data, 'big')
                data = self._recv_exact(message_length)
                if not data:
                    self.connected = False
                    break

                notification = json.loads(data.decode('utf-8'))

                if self.message_callback:
                    self.message_callback(notification)
            except Exception as e:
                if not self.stop_receiving:
                    print(f"Receive error: {e}")
                    self.connected = False
                break

    def set_message_callback(self, callback):
        """Set callback for incoming messages"""
        self.message_callback = callback

    def reconnect_and_login(self):
        """Reconnect and login"""
        if self.reconnect_attempts >= self.max_reconnect_attempts:
            return False

        self.reconnect_attempts += 1

        if self.connect():
            if self.username and self.password:
                success, _ = self.login(self.username, self.password)
                if success:
                    self.start_receiving()
                    self.sync_pending_messages()
                    return True
        return False

    def clear_local_storage(self):
        """Clear all local messages"""
        if self.local_storage:
            self.local_storage.clear_all_messages()
            return True
        return False


class LoginWindow(QWidget):
    """Login window with secure credential storage"""

    def __init__(self):
        super().__init__()
        self.network_client = NetworkClient()
        self.translator = Translator('en')
        self.init_ui()
        self.load_saved_credentials()
        self.load_settings()

    def load_settings(self):
        """Load saved language settings"""
        try:
            if os.path.exists('settings.json'):
                with open('settings.json', 'r') as f:
                    settings = json.load(f)
                    language = settings.get('language', 'en')
                    self.translator = Translator(language)
                    self.update_ui_text()
        except:
            pass

    def update_ui_text(self):
        """Update UI text after language change"""
        self.setWindowTitle(self.translator.tr('login_title'))

    def init_ui(self):
        self.setWindowTitle(self.translator.tr('login_title'))
        self.setFixedSize(450, 350)

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

        self.offline_check = QCheckBox(self.translator.tr('offline_mode'))
        self.offline_check.stateChanged.connect(self.on_offline_changed)
        layout.addWidget(self.offline_check)

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

    def on_offline_changed(self, state):
        """Handle offline mode checkbox change"""
        if state == Qt.Checked:
            self.connect_label.setText(self.translator.tr('offline_mode_info'))
            self.connect_label.setStyleSheet("color: orange")
            self.login_btn.setEnabled(True)
            self.register_btn.setEnabled(False)
        else:
            self.connect_to_server()

    def load_saved_credentials(self):
        """Load saved credentials using JSON"""
        try:
            if os.path.exists('credentials.json'):
                with open('credentials.json', 'r') as f:
                    data = json.load(f)
                    if 'username' in data:
                        self.username_input.setText(data['username'])
                    if 'remember' in data and data['remember']:
                        self.remember_check.setChecked(True)
        except:
            pass

    def save_credentials(self):
        """Save credentials using JSON"""
        try:
            data = {
                'username': self.username_input.text(),
                'remember': self.remember_check.isChecked()
            }
            with open('credentials.json', 'w') as f:
                json.dump(data, f)
        except:
            pass

    def connect_to_server(self):
        """Connect to server"""
        if self.offline_check.isChecked():
            return

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
        """Login to server or use offline mode"""
        username = self.username_input.text().strip()
        password = self.password_input.text()

        if not username:
            QMessageBox.warning(self, "Error", self.translator.tr('username_error'))
            return

        if not password:
            QMessageBox.warning(self, "Error", self.translator.tr('password_error'))
            return

        offline_mode = self.offline_check.isChecked()

        self.login_btn.setEnabled(False)
        self.login_btn.setText(self.translator.tr('logging_in'))
        QApplication.processEvents()

        success, message = self.network_client.login(username, password)

        if success:
            self.save_credentials()
            time.sleep(0.5)

            if not offline_mode:
                self.network_client.start_receiving()

            self.main_window = MainWindow(self.network_client, self.translator, offline_mode)
            self.main_window.show()
            self.close()
        else:
            QMessageBox.warning(self, "Error", message)
            self.login_btn.setEnabled(True)
            self.login_btn.setText(self.translator.tr('login_btn'))

    def open_register(self):
        """Open registration window"""
        if self.offline_check.isChecked():
            QMessageBox.warning(self, "Error", "Cannot register in offline mode")
            return

        if not self.network_client.connected:
            QMessageBox.warning(self, "Error", self.translator.tr('connection_error'))
            return

        self.register_window = RegisterWindow(self.network_client, self, self.translator)
        self.register_window.show()


class RegisterWindow(QWidget):
    """Registration window with validation"""

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
        self.email_input.setPlaceholderText(self.translator.tr('email_label'))
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
        """Register new user"""
        username = self.username_input.text().strip()
        email = self.email_input.text().strip()
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

        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            self.status_label.setText(self.translator.tr('email_error'))
            self.status_label.setStyleSheet("color: red")
            return

        self.register_btn.setEnabled(False)
        self.register_btn.setText(self.translator.tr('registration'))
        QApplication.processEvents()

        success, message = self.network_client.register(username, email, password)

        if success:
            self.status_label.setText("Registration successful!")
            self.status_label.setStyleSheet("color: green")
            QMessageBox.information(self, "Success", self.translator.tr('registration_success'))
            self.close()
        else:
            self.status_label.setText(message)
            self.status_label.setStyleSheet("color: red")
            self.register_btn.setEnabled(True)
            self.register_btn.setText(self.translator.tr('register_btn'))


class MainWindow(QMainWindow):
    """Main messenger window with offline support"""

    def __init__(self, network_client, translator, offline_mode=False):
        super().__init__()
        self.network_client = network_client
        self.translator = translator
        self.username = network_client.username
        self.current_chat = None
        self.current_theme = 'light'
        self.offline_mode = offline_mode
        self.message_ids = {}  # Store message IDs for deletion

        if not offline_mode:
            self.network_client.set_message_callback(self.handle_incoming_message)

        self.init_ui()
        self.load_contacts()
        self.load_avatar()

    def init_ui(self):
        """Initialize UI"""
        title = self.translator.tr('main_title', username=self.username)
        if self.offline_mode:
            title += " (OFFLINE)"
        self.setWindowTitle(title)
        self.setGeometry(100, 100, 900, 600)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)

        left_panel = self.create_left_panel()
        chat_panel = self.create_chat_panel()

        main_layout.addWidget(left_panel, 1)
        main_layout.addWidget(chat_panel, 3)

        self.create_menu()

    def create_menu(self):
        """Create menu bar"""
        menubar = self.menuBar()

        settings_menu = menubar.addMenu(self.translator.tr('settings'))

        theme_action = QAction(self.translator.tr('theme'), self)
        theme_action.triggered.connect(self.change_theme)
        settings_menu.addAction(theme_action)

        language_menu = settings_menu.addMenu(self.translator.tr('language'))

        ru_action = QAction('Русский', self)
        ru_action.triggered.connect(lambda: self.change_language('ru'))
        language_menu.addAction(ru_action)

        en_action = QAction('English', self)
        en_action.triggered.connect(lambda: self.change_language('en'))
        language_menu.addAction(en_action)

        if not self.offline_mode:
            reconnect_action = QAction(self.translator.tr('reconnect'), self)
            reconnect_action.triggered.connect(self.reconnect_to_server)
            settings_menu.addAction(reconnect_action)

            sync_action = QAction(self.translator.tr('sync_messages'), self)
            sync_action.triggered.connect(self.sync_with_server)
            settings_menu.addAction(sync_action)

        settings_menu.addSeparator()

        storage_menu = settings_menu.addMenu(self.translator.tr('offline_storage'))

        clear_local_action = QAction(self.translator.tr('clear_local'), self)
        clear_local_action.triggered.connect(self.clear_local_storage)
        storage_menu.addAction(clear_local_action)

        settings_menu.addSeparator()

        logout_action = QAction(self.translator.tr('logout'), self)
        logout_action.triggered.connect(self.logout)
        settings_menu.addAction(logout_action)

        tools_menu = menubar.addMenu(self.translator.tr('tools'))
        refresh_action = QAction(self.translator.tr('refresh_contacts'), self)
        refresh_action.triggered.connect(self.load_contacts)
        tools_menu.addAction(refresh_action)

    def change_language(self, language):
        """Change language and save preference"""
        try:
            settings = {'language': language}
            with open('settings.json', 'w') as f:
                json.dump(settings, f)

            QMessageBox.information(self, self.translator.tr('language'),
                                    self.translator.tr('language_changed'))
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to change language: {str(e)}")

    def create_left_panel(self):
        """Create left panel with contacts"""
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

        self.username_label = QLabel(self.username + (" (OFFLINE)" if self.offline_mode else ""))
        self.username_label.setAlignment(Qt.AlignCenter)
        self.username_label.setFont(QFont("Arial", 12, QFont.Bold))
        top_layout.addWidget(self.username_label)

        if not self.offline_mode:
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

        if self.offline_mode:
            self.status_label = QLabel("📴 " + self.translator.tr('offline_mode'))
            self.status_label.setStyleSheet("color: orange")
        else:
            self.status_label = QLabel(self.translator.tr('connection_ok'))
            self.status_label.setStyleSheet("color: green")

        status_layout.addWidget(self.status_label)

        if not self.offline_mode:
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
        """Create chat panel with message context menu"""
        chat_widget = QWidget()
        self.chat_layout = QVBoxLayout()

        header_widget = QWidget()
        header_layout = QHBoxLayout()

        self.chat_header = QLabel(self.translator.tr('select_chat'))
        self.chat_header.setFont(QFont("Arial", 14, QFont.Bold))
        header_layout.addWidget(self.chat_header)

        if not self.offline_mode:
            self.file_btn = QPushButton("📎")
            self.file_btn.setFixedSize(40, 40)
            self.file_btn.setToolTip(self.translator.tr('send_file'))
            self.file_btn.clicked.connect(self.send_file)
            self.file_btn.setEnabled(False)
            header_layout.addWidget(self.file_btn)

        header_widget.setLayout(header_layout)
        self.chat_layout.addWidget(header_widget)

        self.messages_area = QTextBrowser()  # Changed to QTextBrowser for better display
        self.messages_area.setOpenLinks(False)
        self.messages_area.setReadOnly(True)

        # Add context menu for messages
        self.messages_area.setContextMenuPolicy(Qt.CustomContextMenu)
        self.messages_area.customContextMenuRequested.connect(self.show_message_context_menu)

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

    def show_message_context_menu(self, position):
        """Show context menu for messages"""
        if not self.current_chat:
            return

        cursor = self.messages_area.cursorForPosition(position)
        cursor.select(QTextCursor.WordUnderCursor)
        selected_text = cursor.selectedText()

        if selected_text and "message_id:" in selected_text:
            # Extract message ID
            parts = selected_text.split("message_id:")
            if len(parts) > 1:
                message_id = parts[1]

                menu = QMenu()

                delete_action = menu.addAction(self.translator.tr('delete_for_all'))
                action = menu.exec_(self.messages_area.mapToGlobal(position))

                if action == delete_action:
                    self.delete_message(message_id)

    def load_avatar(self):
        """Load user avatar"""
        if self.offline_mode:
            self.set_default_avatar()
            return

        try:
            response = self.network_client.get_user_avatar(self.username)
            if response and response.get('status') == 'success' and response.get('avatar'):
                avatar_bytes = base64.b64decode(response['avatar'])
                pixmap = QPixmap()
                if pixmap.loadFromData(avatar_bytes):
                    pixmap = pixmap.scaled(60, 60, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    self.avatar_btn.setIcon(QIcon(pixmap))
                    self.avatar_btn.setIconSize(QSize(60, 60))
                    return
        except Exception as e:
            print(f"Avatar load error: {e}")

        self.set_default_avatar()

    def set_default_avatar(self):
        """Set default avatar icon"""
        pixmap = QPixmap(60, 60)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setBrush(QBrush(QColor(100, 150, 200)))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(5, 5, 50, 50)
        painter.end()
        self.avatar_btn.setIcon(QIcon(pixmap))
        self.avatar_btn.setIconSize(QSize(60, 60))

    def load_contacts(self):
        """Load contacts from server or local storage"""
        self.chat_list.clear()
        contacts = self.network_client.get_contacts()

        for contact in contacts:
            username = contact['username']
            online = contact.get('online', False)

            item = QListWidgetItem(f"{username} {'●' if online else '○'}")
            item.setData(Qt.UserRole, username)

            # Try to load avatar
            if not self.offline_mode:
                try:
                    response = self.network_client.get_user_avatar(username)
                    if response and response.get('status') == 'success' and response.get('avatar'):
                        avatar_bytes = base64.b64decode(response['avatar'])
                        pixmap = QPixmap()
                        if pixmap.loadFromData(avatar_bytes):
                            item.setIcon(QIcon(pixmap))
                except:
                    pass

            self.chat_list.addItem(item)

    def open_chat(self, item):
        """Open chat with selected user"""
        self.current_chat = item.data(Qt.UserRole)
        self.chat_header.setText(self.translator.tr('chat_with', user=self.current_chat))

        if not self.offline_mode:
            self.file_btn.setEnabled(True)

        self.messages_area.clear()
        messages = self.network_client.get_messages(self.current_chat, use_local=self.offline_mode)

        for msg in messages:
            self.display_message(msg)

    def display_message(self, msg):
        """Display a message in the chat area"""
        sender = msg['sender']
        text = msg['message']
        timestamp = msg.get('timestamp', '')

        # Format timestamp
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            formatted_time = dt.strftime("%H:%M")
        except:
            formatted_time = timestamp

        # Generate unique ID for the message
        message_id = f"msg_{int(time.time() * 1000)}"
        self.message_ids[message_id] = msg

        if sender == self.username:
            self.messages_area.append(
                f'<div style="background-color: #e3f2fd; padding: 8px; margin: 4px; border-radius: 10px; float: right; clear: both; max-width: 70%;">'
                f'<b>You</b> [{formatted_time}]<br>{text}'
                f'<br><small style="color: #666;">message_id:{message_id}</small>'
                f'</div><br style="clear: both;">'
            )
        else:
            self.messages_area.append(
                f'<div style="background-color: #f5f5f5; padding: 8px; margin: 4px; border-radius: 10px; float: left; clear: both; max-width: 70%;">'
                f'<b>{sender}</b> [{formatted_time}]<br>{text}'
                f'<br><small style="color: #666;">message_id:{message_id}</small>'
                f'</div><br style="clear: both;">'
            )

    def send_message(self):
        """Send message to current chat"""
        if not self.current_chat:
            return

        message = self.message_input.text().strip()
        if not message:
            return

        if self.network_client.send_message(self.current_chat, message):
            timestamp = datetime.now().isoformat()
            msg = {
                'sender': self.username,
                'receiver': self.current_chat,
                'message': message,
                'timestamp': timestamp
            }
            self.display_message(msg)
            self.message_input.clear()

            # Auto-scroll to bottom
            scrollbar = self.messages_area.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())
        else:
            if self.offline_mode:
                QMessageBox.information(self, "Info", "Message saved locally and will be sent when online")
            else:
                QMessageBox.warning(self, "Error", self.translator.tr('message_send_failed'))

    def delete_message(self, message_id):
        """Delete message from chat"""
        if message_id not in self.message_ids:
            return

        reply = QMessageBox.question(
            self, self.translator.tr('confirm_delete'),
            self.translator.tr('confirm_delete'),
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            msg = self.message_ids[message_id]
            if not self.offline_mode:
                response = self.network_client.delete_message(message_id, for_all=True)
                if response and response.get('status') == 'success':
                    QMessageBox.information(self, "Success", self.translator.tr('message_deleted'))
                else:
                    QMessageBox.warning(self, "Error", "Failed to delete message")

            # Remove from display
            self.messages_area.clear()
            messages = self.network_client.get_messages(self.current_chat, use_local=self.offline_mode)
            for m in messages:
                self.display_message(m)

    def send_file(self):
        """Send file to current chat"""
        if not self.current_chat:
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            self.translator.tr('select_file'),
            "",
            "All Files (*.*)"
        )
        if file_path:
            file_size = os.path.getsize(file_path)
            if file_size > 5 * 1024 * 1024:
                QMessageBox.warning(self, "Error", self.translator.tr('file_too_large'))
                return

            if self.network_client.send_file(self.current_chat, file_path):
                QMessageBox.information(self, "Success", self.translator.tr('file_sent'))
            else:
                QMessageBox.warning(self, "Error", self.translator.tr('file_send_failed'))

    def search_users(self):
        """Search for users and add to chat list"""
        if self.offline_mode:
            QMessageBox.information(self, "Info", "Cannot search in offline mode")
            return

        dialog = SearchDialog(self.network_client, self, self.translator)
        dialog.exec_()
        # Refresh contacts after dialog closes
        self.load_contacts()

    def open_profile_settings(self):
        """Open profile settings dialog"""
        if self.offline_mode:
            QMessageBox.information(self, "Info", "Cannot update profile in offline mode")
            return

        dialog = ProfileDialog(self.network_client, self.translator)
        if dialog.exec_():
            self.load_avatar()

    def handle_incoming_message(self, notification):
        """Handle incoming messages"""
        msg_type = notification.get('type')

        if msg_type == 'new_message':
            sender = notification.get('sender')
            message = notification.get('message')

            try:
                if self.network_client.fernet and message:
                    message = self.network_client.fernet.decrypt(message.encode('utf-8')).decode('utf-8')
            except Exception as e:
                print(f"Decryption error: {e}")
                message = self.translator.tr('encryption_error')

            if self.current_chat == sender:
                timestamp = datetime.now().isoformat()
                msg = {
                    'sender': sender,
                    'message': message,
                    'timestamp': timestamp
                }
                self.display_message(msg)

            self.load_contacts()

            # Show notification
            QApplication.alert(self, 0)

    def change_theme(self):
        """Toggle theme"""
        if self.current_theme == 'light':
            self.current_theme = 'dark'
            self.apply_dark_theme()
        else:
            self.current_theme = 'light'
            self.apply_light_theme()

    def apply_dark_theme(self):
        """Apply dark theme"""
        qApp.setStyleSheet("""
            QWidget {
                background-color: #2d2d2d;
                color: #ffffff;
            }
            QLineEdit, QTextEdit, QListWidget {
                background-color: #3d3d3d;
                border: 1px solid #555;
                color: #ffffff;
                padding: 5px;
            }
            QPushButton {
                background-color: #4d4d4d;
                color: #ffffff;
                border: 1px solid #555;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #5d5d5d;
            }
        """)

    def apply_light_theme(self):
        """Apply light theme"""
        qApp.setPalette(qApp.style().standardPalette())
        qApp.setStyleSheet("")

    def reconnect_to_server(self):
        """Reconnect to server"""
        self.status_label.setText(self.translator.tr('reconnecting'))
        if hasattr(self, 'reconnect_btn'):
            self.reconnect_btn.hide()
        QApplication.processEvents()

        if self.network_client.reconnect_and_login():
            self.offline_mode = False
            self.status_label.setText(self.translator.tr('connection_ok'))
            self.status_label.setStyleSheet("color: green")
            self.load_contacts()
            self.setWindowTitle(self.translator.tr('main_title', username=self.username))
            self.username_label.setText(self.username)
        else:
            self.status_label.setText(self.translator.tr('connection_lost'))
            self.status_label.setStyleSheet("color: red")
            if hasattr(self, 'reconnect_btn'):
                self.reconnect_btn.show()

    def sync_with_server(self):
        """Sync messages with server"""
        if self.offline_mode:
            QMessageBox.information(self, "Info", "Already in offline mode")
            return

        self.status_label.setText(self.translator.tr('sync_messages'))
        QApplication.processEvents()

        if self.current_chat:
            messages = self.network_client.get_messages(self.current_chat, use_local=False)
            self.messages_area.clear()
            for msg in messages:
                self.display_message(msg)

        self.status_label.setText(self.translator.tr('sync_complete'))
        QMessageBox.information(self, "Success", self.translator.tr('sync_complete'))

    def clear_local_storage(self):
        """Clear local storage"""
        reply = QMessageBox.question(
            self, self.translator.tr('clear_local'),
            self.translator.tr('clear_local_confirm'),
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            if self.network_client.clear_local_storage():
                QMessageBox.information(self, "Success", self.translator.tr('local_cleared'))
                if self.current_chat:
                    self.messages_area.clear()
            else:
                QMessageBox.warning(self, "Error", "Failed to clear local storage")

    def logout(self):
        """Logout from application"""
        reply = QMessageBox.question(
            self, 'Logout',
            self.translator.tr('logout_confirm'),
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            self.network_client.disconnect()
            self.close()

            login_window = LoginWindow()
            login_window.show()


class ProfileDialog(QDialog):
    """Profile settings dialog"""

    def __init__(self, network_client, translator):
        super().__init__()
        self.network_client = network_client
        self.translator = translator
        self.avatar_data = None
        self.avatar_changed = False
        self.init_ui()
        self.load_current_avatar()

    def init_ui(self):
        self.setWindowTitle(self.translator.tr('profile_settings'))
        self.setFixedSize(400, 400)

        layout = QVBoxLayout()

        layout.addWidget(QLabel(self.translator.tr('change_avatar')))
        self.avatar_label = QLabel()
        self.avatar_label.setFixedSize(100, 100)
        self.avatar_label.setAlignment(Qt.AlignCenter)
        self.set_default_avatar()
        layout.addWidget(self.avatar_label)

        change_avatar_btn = QPushButton(self.translator.tr('change_avatar'))
        change_avatar_btn.clicked.connect(self.change_avatar)
        layout.addWidget(change_avatar_btn)

        layout.addWidget(QLabel(self.translator.tr('new_password')))
        self.new_password = QLineEdit()
        self.new_password.setEchoMode(QLineEdit.Password)
        self.new_password.setPlaceholderText(self.translator.tr('password_keep'))
        layout.addWidget(self.new_password)

        layout.addWidget(QLabel(self.translator.tr('confirm_password')))
        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.confirm_password)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save_changes)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def load_current_avatar(self):
        """Load current user avatar"""
        try:
            response = self.network_client.get_user_avatar(self.network_client.username)
            if response and response.get('status') == 'success' and response.get('avatar'):
                avatar_bytes = base64.b64decode(response['avatar'])
                pixmap = QPixmap()
                if pixmap.loadFromData(avatar_bytes):
                    pixmap = pixmap.scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    self.avatar_label.setPixmap(pixmap)
                    return
        except:
            pass
        self.set_default_avatar()

    def set_default_avatar(self):
        """Set default avatar"""
        pixmap = QPixmap(100, 100)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setBrush(QBrush(QColor(100, 150, 200)))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(10, 10, 80, 80)
        painter.end()
        self.avatar_label.setPixmap(pixmap)

    def change_avatar(self):
        """Change avatar"""
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            self.translator.tr('change_avatar'),
            "",
            "Images (*.png *.jpg *.jpeg *.bmp)"
        )
        if file_name:
            try:
                if os.path.getsize(file_name) > 1024 * 1024:
                    QMessageBox.warning(self, "Error", self.translator.tr('avatar_too_large'))
                    return

                with open(file_name, 'rb') as f:
                    self.avatar_data = base64.b64encode(f.read()).decode()
                    self.avatar_changed = True

                pixmap = QPixmap(file_name).scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                self.avatar_label.setPixmap(pixmap)
            except Exception as e:
                QMessageBox.warning(self, "Error", f"{self.translator.tr('avatar_load_failed')}: {e}")

    def save_changes(self):
        """Save profile changes"""
        new_password = self.new_password.text()
        confirm = self.confirm_password.text()

        if not self.avatar_changed and not new_password:
            QMessageBox.warning(self, "Error", self.translator.tr('no_changes'))
            return

        if new_password and new_password != confirm:
            QMessageBox.warning(self, "Error", self.translator.tr('passwords_match'))
            return

        if new_password and len(new_password) < 6:
            QMessageBox.warning(self, "Error", self.translator.tr('password_min'))
            return

        avatar_to_send = self.avatar_data if self.avatar_changed else None

        response = self.network_client.update_profile(
            avatar_data=avatar_to_send,
            password=new_password if new_password else None
        )

        if response and response.get('status') == 'success':
            QMessageBox.information(self, "Success", self.translator.tr('profile_updated'))
            self.accept()
        else:
            error_msg = response.get('message', 'Unknown error') if response else 'Connection error'
            QMessageBox.warning(self, "Error", f"{self.translator.tr('profile_error')}: {error_msg}")


class SearchDialog(QDialog):
    """User search dialog"""

    def __init__(self, network_client, main_window, translator):
        super().__init__()
        self.network_client = network_client
        self.main_window = main_window
        self.translator = translator
        self.selected_user = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle(self.translator.tr('search_users'))
        self.setFixedSize(400, 500)

        layout = QVBoxLayout()

        layout.addWidget(QLabel(self.translator.tr('search_query_label')))

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(self.translator.tr('search_placeholder'))
        self.search_input.returnPressed.connect(self.search)
        layout.addWidget(self.search_input)

        self.search_btn = QPushButton(self.translator.tr('search_btn'))
        self.search_btn.clicked.connect(self.search)
        layout.addWidget(self.search_btn)

        self.results_list = QListWidget()
        self.results_list.itemClicked.connect(self.on_user_selected)
        layout.addWidget(self.results_list)

        # Add button to add user to chat list
        self.add_btn = QPushButton(self.translator.tr('add_to_chat'))
        self.add_btn.clicked.connect(self.add_user_to_chat)
        self.add_btn.setEnabled(False)
        layout.addWidget(self.add_btn)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def search(self):
        """Search for users"""
        query = self.search_input.text().strip()
        if not query:
            QMessageBox.warning(self, "Error", self.translator.tr('enter_query'))
            return

        if len(query) < 2:
            QMessageBox.warning(self, "Error", self.translator.tr('query_too_short'))
            return

        self.results_list.clear()
        self.selected_user = None
        self.add_btn.setEnabled(False)

        # Call search_users
        response = self.network_client.search_users(query)

        # Check if response is None (connection error)
        if response is None:
            QMessageBox.warning(self, "Error", self.translator.tr('search_error'))
            return

        if response.get('status') == 'success':
            users = response.get('users', [])
            if users:
                for user in users:
                    username = user['username']
                    if username != self.main_window.username:
                        item = QListWidgetItem(username)
                        self.results_list.addItem(item)
            else:
                QMessageBox.information(self, "Result", self.translator.tr('no_users'))
        else:
            error_msg = response.get('message', 'Server error')
            QMessageBox.warning(self, "Error", f"{self.translator.tr('search_failed')}: {error_msg}")

    def on_user_selected(self, item):
        """Handle user selection from list"""
        self.selected_user = item.text()
        self.add_btn.setEnabled(True)

    def add_user_to_chat(self):
        """Add selected user to chat list by sending a greeting message"""
        if not self.selected_user:
            QMessageBox.warning(self, "Error", "No user selected")
            return

        # Send a greeting message to create a chat history
        greeting_message = "Hello! I've added you to my contacts."
        if self.network_client.send_message(self.selected_user, greeting_message):
            QMessageBox.information(self, "Success",
                                    self.translator.tr('user_added', user=self.selected_user))
            self.accept()
        else:
            QMessageBox.warning(self, "Error", "Failed to add user to chat list")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    login_window = LoginWindow()
    login_window.show()
    sys.exit(app.exec_())