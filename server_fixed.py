import sys
import socket
import threading
import json
import sqlite3
import base64
import hashlib
import os
import secrets
import time
import re
from datetime import datetime, timedelta
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecureServer:
    """Secure messaging server with encryption, authentication, and auto-cleanup"""

    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.clients = {}
        self.lock = threading.Lock()
        self.heartbeat_interval = 30
        self.max_message_size = 10 * 1024 * 1024  # 10MB limit
        self.rate_limit = {}
        self.message_retention_hours = 24  # Delete messages after 24 hours
        self.max_login_attempts = 5
        self.lockout_time = 900  # 15 minutes in seconds
        self.init_database()
        self.start_cleanup_thread()

    def init_database(self):
        """Initialize SQLite database with proper schema and cleanup triggers"""
        self.conn = sqlite3.connect('secure_messenger.db', check_same_thread=False)
        self.cursor = self.conn.cursor()

        # Создаем таблицы
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                avatar TEXT,
                registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                public_key TEXT,
                session_token TEXT,
                token_expiry TIMESTAMP
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                local_id TEXT UNIQUE,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                delivered INTEGER DEFAULT 0,
                read_status INTEGER DEFAULT 0,
                delete_after_delivery INTEGER DEFAULT 1
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_data TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                delivered INTEGER DEFAULT 0,
                delete_after_delivery INTEGER DEFAULT 1
            )
        ''')

        # Добавляем столбец expires_at если его нет
        self.add_column_if_not_exists('messages', 'expires_at', 'TIMESTAMP')
        self.add_column_if_not_exists('files', 'expires_at', 'TIMESTAMP')

        # Создаем индексы
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_sender_receiver ON messages(sender, receiver)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages(expires_at)')

        # Создаем триггер для автоочистки
        self.cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS set_message_expiry 
            AFTER INSERT ON messages
            BEGIN
                UPDATE messages 
                SET expires_at = datetime('now', '+24 hours')
                WHERE id = NEW.id AND expires_at IS NULL;
            END;
        ''')

        # Триггер для файлов
        self.cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS set_file_expiry 
            AFTER INSERT ON files
            BEGIN
                UPDATE files 
                SET expires_at = datetime('now', '+24 hours')
                WHERE id = NEW.id AND expires_at IS NULL;
            END;
        ''')

        self.conn.commit()
        print("Database initialized successfully")

    def add_column_if_not_exists(self, table, column, column_type):
        """Добавить столбец если он не существует"""
        try:
            self.cursor.execute(f"PRAGMA table_info({table})")
            columns = [col[1] for col in self.cursor.fetchall()]
            if column not in columns:
                self.cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")
                print(f"Added column {column} to table {table}")
        except Exception as e:
            print(f"Error adding column {column} to {table}: {e}")

    def generate_encryption_key(self, password, salt=None):
        """Generate encryption key from password using PBKDF2"""
        if salt is None:
            salt = secrets.token_bytes(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key.decode('utf-8'), salt.hex()

    def hash_password(self, password, salt=None):
        """Securely hash password using PBKDF2-HMAC-SHA512"""
        if salt is None:
            salt = secrets.token_hex(32)

        password_hash = hashlib.pbkdf2_hmac(
            'sha512',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            210000  # High iteration count for security
        )
        return base64.b64encode(password_hash).decode('utf-8'), salt

    def verify_password(self, password, stored_hash, salt):
        """Verify password against stored hash"""
        password_hash, _ = self.hash_password(password, salt)
        return secrets.compare_digest(password_hash, stored_hash)

    def check_rate_limit(self, ip_address, max_requests=100, window=60):
        """Check if IP has exceeded rate limit"""
        now = time.time()

        if ip_address not in self.rate_limit:
            self.rate_limit[ip_address] = {'count': 1, 'timestamp': now}
            return True

        user_rate = self.rate_limit[ip_address]
        if now - user_rate['timestamp'] > window:
            self.rate_limit[ip_address] = {'count': 1, 'timestamp': now}
            return True

        if user_rate['count'] >= max_requests:
            return False

        user_rate['count'] += 1
        return True

    def cleanup_old_messages(self):
        """Cleanup old messages from database"""
        try:
            # Delete messages older than retention period
            self.cursor.execute('''
                DELETE FROM messages 
                WHERE expires_at IS NOT NULL 
                AND expires_at < datetime('now')
            ''')

            # Delete messages marked for deletion after delivery
            self.cursor.execute('''
                DELETE FROM messages 
                WHERE delete_after_delivery = 1 
                AND delivered = 1 
                AND timestamp < datetime('now', '-1 hour')
            ''')

            # Delete old files
            self.cursor.execute('''
                DELETE FROM files 
                WHERE expires_at IS NOT NULL 
                AND expires_at < datetime('now')
            ''')

            self.conn.commit()
            deleted_count = self.cursor.rowcount
            if deleted_count > 0:
                print(f"Cleaned up {deleted_count} old messages/files")
        except Exception as e:
            print(f"Cleanup error: {e}")

    def start_cleanup_thread(self):
        """Start background thread for periodic cleanup"""

        def cleanup_worker():
            while self.running:
                time.sleep(3600)  # Run every hour
                if self.running:
                    self.cleanup_old_messages()

        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()

    def start(self):
        """Start the server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            self.server_socket.settimeout(1)
            self.running = True

            print(f"Server started on {self.host}:{self.port}")
            print(f"Message retention: {self.message_retention_hours} hours")
            print(f"Auto-cleanup enabled")

            accept_thread = threading.Thread(target=self.accept_connections, daemon=True)
            accept_thread.start()

            return True
        except Exception as e:
            print(f"Server start error: {e}")
            return False

    def stop(self):
        """Stop the server and close all connections"""
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

        print("Server stopped")

    def accept_connections(self):
        """Accept incoming client connections"""
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                client_socket.settimeout(30)
                ip_address = address[0]

                if not self.check_rate_limit(ip_address):
                    print(f"Rate limit exceeded for {address}")
                    client_socket.close()
                    continue

                print(f"New connection from {address}")

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
                    print(f"Connection accept error: {e}")
                break

    def _recv_exact(self, sock, n):
        """Receive exact number of bytes from socket"""
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
        """Send all data through socket"""
        try:
            sock.sendall(data)
            return True
        except:
            return False

    def validate_username(self, username):
        """Validate username format"""
        if not username or len(username) < 3 or len(username) > 30:
            return False
        # Allow letters, numbers, underscores, and hyphens
        return bool(re.match(r'^[a-zA-Z0-9_-]+$', username))

    def validate_email(self, email):
        """Validate email format using regex"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def handle_client(self, client_socket, address):
        """Handle individual client connection"""
        username = None
        ip_address = address[0]

        try:
            while self.running:
                try:
                    length_data = self._recv_exact(client_socket, 4)
                    if not length_data:
                        break

                    message_length = int.from_bytes(length_data, 'big')

                    if message_length <= 0 or message_length > self.max_message_size:
                        print(f"Invalid message length from {address}")
                        break

                    data = self._recv_exact(client_socket, message_length)
                    if not data:
                        break

                    try:
                        request = json.loads(data.decode('utf-8'))
                    except json.JSONDecodeError as e:
                        print(f"JSON decode error from {address}: {e}")
                        error_response = json.dumps({
                            'status': 'error',
                            'message': 'Invalid request format'
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

                    if username and not self.check_rate_limit(ip_address, max_requests=500):
                        response = {'status': 'error', 'message': 'Rate limit exceeded'}
                        response_data = json.dumps(response).encode('utf-8')
                        self._send_all(client_socket, len(response_data).to_bytes(4, 'big'))
                        self._send_all(client_socket, response_data)
                        continue

                    response = self.process_request(request, username, ip_address)

                    if request.get('action') in ['register', 'login'] and response.get('status') == 'success':
                        username = request.get('username')
                        with self.lock:
                            self.clients[username] = {
                                'socket': client_socket,
                                'address': address,
                                'last_active': datetime.now(),
                                'ip': ip_address
                            }
                        print(f"User {username} authenticated from {address}")

                    response_data = json.dumps(response).encode('utf-8')
                    if not self._send_all(client_socket, len(response_data).to_bytes(4, 'big')):
                        break
                    if not self._send_all(client_socket, response_data):
                        break

                except Exception as e:
                    print(f"Client handling error: {e}")
                    break

        except Exception as e:
            print(f"Client handler exception: {e}")
        finally:
            if username:
                with self.lock:
                    if username in self.clients:
                        del self.clients[username]
                print(f"User {username} disconnected")

            try:
                client_socket.close()
            except:
                pass

    def process_request(self, request, username, ip_address):
        """Process client requests with input validation and logging"""
        action = request.get('action')

        # Log request (without sensitive data)
        safe_request = request.copy()
        if 'password' in safe_request:
            safe_request['password'] = '***'
        if 'file_data' in safe_request:
            safe_request['file_data'] = f"[FILE_DATA:{len(safe_request['file_data'])}]"

        print(f"Processing {action} for user {username} from {ip_address}")

        try:
            if action == 'register':
                return self.handle_register(request, ip_address)
            elif action == 'login':
                return self.handle_login(request, ip_address)
            elif action == 'send_message':
                return self.handle_send_message(request, username)
            elif action == 'get_messages':
                return self.handle_get_messages(request, username)
            elif action == 'send_file':
                return self.handle_send_file(request, username)
            elif action == 'get_files':
                return self.handle_get_files(request, username)
            elif action == 'get_contacts':
                return self.handle_get_contacts(request, username)
            elif action == 'search_users':
                return self.handle_search_users(request)
            elif action == 'update_profile':
                return self.handle_update_profile(request, username)
            elif action == 'get_user_avatar':
                return self.handle_get_user_avatar(request)
            elif action == 'delete_message':
                return self.handle_delete_message(request, username)
            else:
                return {'status': 'error', 'message': 'Unknown action'}
        except Exception as e:
            print(f"Request processing error: {e}")
            return {'status': 'error', 'message': 'Server error'}

    def handle_register(self, request, ip_address):
        """Handle user registration with enhanced security"""
        username = request.get('username', '').strip()
        email = request.get('email', '').strip().lower()
        password = request.get('password', '')

        if not self.validate_username(username):
            return {'status': 'error', 'message': 'Invalid username format (3-30 chars, letters, numbers, _, -)'}

        if not self.validate_email(email):
            return {'status': 'error', 'message': 'Invalid email format'}

        if len(password) < 8:
            return {'status': 'error', 'message': 'Password must be at least 8 characters'}

        # Check for common passwords
        common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']
        if password.lower() in common_passwords:
            return {'status': 'error', 'message': 'Password is too common'}

        try:
            self.cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
            if self.cursor.fetchone():
                return {'status': 'error', 'message': 'Username or email already exists'}

            password_hash, salt = self.hash_password(password)

            self.cursor.execute('''
                INSERT INTO users (username, email, password_hash, salt, failed_attempts)
                VALUES (?, ?, ?, ?, 0)
            ''', (username, email, password_hash, salt))
            self.conn.commit()

            return {
                'status': 'success',
                'message': 'Registration successful'
            }
        except sqlite3.IntegrityError:
            return {'status': 'error', 'message': 'Username or email already exists'}
        except Exception as e:
            print(f"Registration error: {e}")
            return {'status': 'error', 'message': 'Registration failed'}

    def handle_login(self, request, ip_address):
        """Handle user login with enhanced security and rate limiting"""
        username = request.get('username', '').strip()
        password = request.get('password', '')

        if not username or not password:
            return {'status': 'error', 'message': 'Username and password required'}

        try:
            self.cursor.execute('''
                SELECT password_hash, salt, failed_attempts, locked_until
                FROM users WHERE username = ?
            ''', (username,))

            user = self.cursor.fetchone()
            if not user:
                # Simulate password check to prevent timing attacks
                self.verify_password(password, secrets.token_hex(64), secrets.token_hex(32))
                time.sleep(0.1)  # Add small delay to prevent brute force
                return {'status': 'error', 'message': 'Invalid credentials'}

            password_hash, salt, failed_attempts, locked_until = user

            if locked_until:
                lock_time = datetime.fromisoformat(locked_until)
                if datetime.now() < lock_time:
                    remaining = (lock_time - datetime.now()).seconds // 60
                    return {'status': 'error', 'message': f'Account locked. Try again in {remaining} minutes.'}
                else:
                    self.cursor.execute(
                        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?",
                        (username,)
                    )
                    self.conn.commit()

            if not self.verify_password(password, password_hash, salt):
                failed_attempts = (failed_attempts or 0) + 1

                if failed_attempts >= self.max_login_attempts:
                    lock_until = datetime.now() + timedelta(seconds=self.lockout_time)
                    self.cursor.execute(
                        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
                        (failed_attempts, lock_until.isoformat(), username)
                    )
                    self.conn.commit()
                    return {'status': 'error', 'message': 'Account locked due to too many failed attempts'}
                else:
                    self.cursor.execute(
                        "UPDATE users SET failed_attempts = ? WHERE username = ?",
                        (failed_attempts, username)
                    )
                    self.conn.commit()
                    remaining = self.max_login_attempts - failed_attempts
                    return {'status': 'error', 'message': f'Invalid credentials. {remaining} attempts remaining.'}

            # Successful login
            self.cursor.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE username = ?",
                (datetime.now().isoformat(), username)
            )
            self.conn.commit()

            return {
                'status': 'success',
                'message': 'Login successful'
            }
        except Exception as e:
            print(f"Login error: {e}")
            return {'status': 'error', 'message': 'Login failed'}

    def handle_send_message(self, request, username):
        """Handle sending encrypted messages with auto-delete flag"""
        if not username:
            return {'status': 'error', 'message': 'Not authenticated'}

        receiver = request.get('receiver', '').strip()
        message = request.get('message', '')
        local_id = request.get('local_id', '')

        if not receiver or not message:
            return {'status': 'error', 'message': 'Receiver and message required'}

        if len(message) > 10000:
            return {'status': 'error', 'message': 'Message too long'}

        try:
            self.cursor.execute("SELECT id FROM users WHERE username = ?", (receiver,))
            if not self.cursor.fetchone():
                return {'status': 'error', 'message': 'Receiver not found'}

            # Store encrypted message
            self.cursor.execute('''
                INSERT INTO messages (local_id, sender, receiver, message, delivered, delete_after_delivery)
                VALUES (?, ?, ?, ?, 0, 1)
            ''', (local_id, username, receiver, message))
            self.conn.commit()

            message_id = self.cursor.lastrowid

            # Notify receiver if online
            with self.lock:
                if receiver in self.clients:
                    try:
                        notification = {
                            'type': 'new_message',
                            'sender': username,
                            'message': message,
                            'timestamp': datetime.now().isoformat(),
                            'message_id': message_id
                        }
                        notification_data = json.dumps(notification).encode('utf-8')
                        receiver_socket = self.clients[receiver]['socket']
                        self._send_all(receiver_socket, len(notification_data).to_bytes(4, 'big'))
                        self._send_all(receiver_socket, notification_data)

                        # Mark as delivered
                        self.cursor.execute(
                            "UPDATE messages SET delivered = 1 WHERE id = ?",
                            (message_id,)
                        )
                        self.conn.commit()
                    except Exception as e:
                        print(f"Notification error: {e}")

            return {'status': 'success', 'message': 'Message sent', 'message_id': message_id}
        except Exception as e:
            print(f"Send message error: {e}")
            return {'status': 'error', 'message': 'Failed to send message'}

    def handle_get_messages(self, request, username):
        """Retrieve messages for user and mark for deletion"""
        if not username:
            return {'status': 'error', 'message': 'Not authenticated'}

        contact = request.get('contact', '').strip()

        try:
            self.cursor.execute('''
                SELECT id, local_id, sender, receiver, message, timestamp
                FROM messages
                WHERE ((sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?))
                AND delivered = 0
                ORDER BY timestamp ASC
                LIMIT 100
            ''', (username, contact, contact, username))

            messages = []
            message_ids = []

            for row in self.cursor.fetchall():
                messages.append({
                    'id': row[0],
                    'local_id': row[1],
                    'sender': row[2],
                    'receiver': row[3],
                    'message': row[4],
                    'timestamp': row[5]
                })
                message_ids.append(row[0])

            # Mark messages as delivered
            if message_ids:
                self.cursor.execute(f'''
                    UPDATE messages 
                    SET delivered = 1 
                    WHERE id IN ({','.join('?' * len(message_ids))})
                ''', message_ids)
                self.conn.commit()

            return {'status': 'success', 'messages': messages}
        except Exception as e:
            print(f"Get messages error: {e}")
            return {'status': 'error', 'message': 'Failed to retrieve messages'}

    def handle_send_file(self, request, username):
        """Handle file sending with size limit (5MB)"""
        if not username:
            return {'status': 'error', 'message': 'Not authenticated'}

        receiver = request.get('receiver', '').strip()
        file_name = request.get('file_name', '').strip()
        file_data = request.get('file_data', '')

        if not receiver or not file_name or not file_data:
            return {'status': 'error', 'message': 'Invalid file data'}

        file_size = len(file_data)
        if file_size > 5 * 1024 * 1024:
            return {'status': 'error', 'message': 'File too large (max 5MB)'}

        try:
            self.cursor.execute("SELECT id FROM users WHERE username = ?", (receiver,))
            if not self.cursor.fetchone():
                return {'status': 'error', 'message': 'Receiver not found'}

            self.cursor.execute('''
                INSERT INTO files (sender, receiver, file_name, file_data, file_size, delivered, delete_after_delivery)
                VALUES (?, ?, ?, ?, ?, 0, 1)
            ''', (username, receiver, file_name, file_data, file_size))
            self.conn.commit()

            return {'status': 'success', 'message': 'File sent'}
        except Exception as e:
            print(f"Send file error: {e}")
            return {'status': 'error', 'message': 'Failed to send file'}

    def handle_get_files(self, request, username):
        """Retrieve files for user and mark for deletion"""
        if not username:
            return {'status': 'error', 'message': 'Not authenticated'}

        contact = request.get('contact', '').strip()

        try:
            self.cursor.execute('''
                SELECT sender, receiver, file_name, file_data, timestamp
                FROM files
                WHERE ((sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?))
                AND delivered = 0
                ORDER BY timestamp ASC
            ''', (username, contact, contact, username))

            files = []
            for row in self.cursor.fetchall():
                files.append({
                    'sender': row[0],
                    'receiver': row[1],
                    'file_name': row[2],
                    'file_data': row[3],
                    'timestamp': row[4]
                })

            # Mark files as delivered
            self.cursor.execute('''
                UPDATE files 
                SET delivered = 1 
                WHERE ((sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?))
                AND delivered = 0
            ''', (username, contact, contact, username))
            self.conn.commit()

            return {'status': 'success', 'files': files}
        except Exception as e:
            print(f"Get files error: {e}")
            return {'status': 'error', 'message': 'Failed to retrieve files'}

    def handle_get_contacts(self, request, username):
        """Get list of users that have chatted with this user"""
        if not username:
            return {'status': 'error', 'message': 'Not authenticated'}

        try:
            self.cursor.execute('''
                SELECT DISTINCT 
                    CASE 
                        WHEN sender = ? THEN receiver 
                        ELSE sender 
                    END as contact
                FROM messages
                WHERE sender = ? OR receiver = ?
                UNION
                SELECT DISTINCT 
                    CASE 
                        WHEN sender = ? THEN receiver 
                        ELSE sender 
                    END as contact
                FROM files
                WHERE sender = ? OR receiver = ?
            ''', (username, username, username, username, username, username))

            contacts = [row[0] for row in self.cursor.fetchall()]

            contacts_with_status = []
            for contact in contacts:
                with self.lock:
                    online = contact in self.clients
                contacts_with_status.append({
                    'username': contact,
                    'online': online
                })

            return {'status': 'success', 'contacts': contacts_with_status}
        except Exception as e:
            print(f"Get contacts error: {e}")
            return {'status': 'error', 'message': 'Failed to retrieve contacts'}

    def handle_search_users(self, request):
        """Search for users by username - NO authentication required"""
        query = request.get('query', '').strip()

        if not query or len(query) < 2:
            return {'status': 'error', 'message': 'Query too short'}

        try:
            self.cursor.execute(
                "SELECT username FROM users WHERE username LIKE ? AND username != ? LIMIT 50",
                (f"%{query}%", query)
            )

            users = [{'username': row[0]} for row in self.cursor.fetchall()]

            return {'status': 'success', 'users': users}
        except Exception as e:
            print(f"Search users error: {e}")
            return {'status': 'error', 'message': 'Search failed'}

    def handle_update_profile(self, request, username):
        """Update user profile (avatar and/or password)"""
        if not username:
            return {'status': 'error', 'message': 'Not authenticated'}

        avatar_data = request.get('avatar_data')
        new_password = request.get('password')

        if not avatar_data and not new_password:
            return {'status': 'error', 'message': 'No changes to save'}

        try:
            if avatar_data:
                if len(avatar_data) > 1024 * 1024:
                    return {'status': 'error', 'message': 'Avatar too large (max 1MB)'}

                self.cursor.execute(
                    "UPDATE users SET avatar = ? WHERE username = ?",
                    (avatar_data, username)
                )

            if new_password:
                if len(new_password) < 8:
                    return {'status': 'error', 'message': 'Password must be at least 8 characters'}

                password_hash, salt = self.hash_password(new_password)
                self.cursor.execute(
                    "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
                    (password_hash, salt, username)
                )

            self.conn.commit()
            return {'status': 'success', 'message': 'Profile updated'}
        except Exception as e:
            print(f"Update profile error: {e}")
            return {'status': 'error', 'message': 'Failed to update profile'}

    def handle_get_user_avatar(self, request):
        """Get user's avatar"""
        username = request.get('username', '').strip()

        if not username:
            return {'status': 'error', 'message': 'Username required'}

        try:
            self.cursor.execute("SELECT avatar FROM users WHERE username = ?", (username,))
            result = self.cursor.fetchone()

            if result and result[0]:
                return {'status': 'success', 'avatar': result[0]}
            else:
                return {'status': 'success', 'avatar': None}
        except Exception as e:
            print(f"Get avatar error: {e}")
            return {'status': 'error', 'message': 'Failed to get avatar'}

    def handle_delete_message(self, request, username):
        """Delete message from server"""
        if not username:
            return {'status': 'error', 'message': 'Not authenticated'}

        message_id = request.get('message_id')
        for_all = request.get('for_all', False)

        if not message_id:
            return {'status': 'error', 'message': 'Message ID required'}

        try:
            # Check if user has permission to delete this message
            self.cursor.execute('''
                SELECT sender, receiver FROM messages WHERE id = ?
            ''', (message_id,))

            result = self.cursor.fetchone()
            if not result:
                return {'status': 'error', 'message': 'Message not found'}

            sender, receiver = result

            if not for_all and username != sender:
                return {'status': 'error', 'message': 'Cannot delete other user\'s message'}

            # Delete the message
            self.cursor.execute('DELETE FROM messages WHERE id = ?', (message_id,))
            self.conn.commit()

            # Notify other user if online
            other_user = receiver if username == sender else sender
            with self.lock:
                if other_user in self.clients and for_all:
                    try:
                        notification = {
                            'type': 'message_deleted',
                            'message_id': message_id,
                            'deleted_by': username
                        }
                        notification_data = json.dumps(notification).encode('utf-8')
                        other_socket = self.clients[other_user]['socket']
                        self._send_all(other_socket, len(notification_data).to_bytes(4, 'big'))
                        self._send_all(other_socket, notification_data)
                    except:
                        pass

            return {'status': 'success', 'message': 'Message deleted'}
        except Exception as e:
            print(f"Delete message error: {e}")
            return {'status': 'error', 'message': 'Failed to delete message'}

    def send_broadcast(self, subject, message):
        """Send broadcast message to all online users"""
        sent_count = 0
        with self.lock:
            for username, client_data in self.clients.items():
                try:
                    notification = {
                        'type': 'broadcast',
                        'subject': subject,
                        'message': message
                    }
                    notification_data = json.dumps(notification).encode('utf-8')
                    self._send_all(client_data['socket'], len(notification_data).to_bytes(4, 'big'))
                    self._send_all(client_data['socket'], notification_data)
                    sent_count += 1
                except:
                    pass
        return sent_count


class UserEditDialog(QDialog):
    """Dialog for editing user information"""

    def __init__(self, username, cursor, conn, parent=None):
        super().__init__(parent)
        self.username = username
        self.cursor = cursor
        self.conn = conn
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle(f"Edit User: {self.username}")
        self.setFixedSize(400, 300)

        layout = QVBoxLayout()

        layout.addWidget(QLabel("Email:"))
        self.email_input = QLineEdit()
        layout.addWidget(self.email_input)

        self.reset_pwd_btn = QPushButton("Reset Password")
        self.reset_pwd_btn.clicked.connect(self.reset_password)
        layout.addWidget(self.reset_pwd_btn)

        self.load_user_data()

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save_changes)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def load_user_data(self):
        """Load user data from database"""
        try:
            self.cursor.execute("SELECT email FROM users WHERE username = ?", (self.username,))
            result = self.cursor.fetchone()
            if result:
                self.email_input.setText(result[0])
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load user data: {e}")

    def save_changes(self):
        """Save changes to database"""
        email = self.email_input.text().strip()

        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            QMessageBox.warning(self, "Error", "Invalid email format")
            return

        try:
            self.cursor.execute(
                "UPDATE users SET email = ? WHERE username = ?",
                (email, self.username)
            )
            self.conn.commit()
            QMessageBox.information(self, "Success", "User updated successfully")
            self.accept()
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Error", "Email already exists")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to update user: {e}")

    def reset_password(self):
        """Reset user password"""
        new_password, ok = QInputDialog.getText(
            self, "Reset Password",
            "Enter new password:",
            QLineEdit.Password
        )

        if ok and new_password:
            if len(new_password) < 8:
                QMessageBox.warning(self, "Error", "Password must be at least 8 characters")
                return

            try:
                server = SecureServer()
                password_hash, salt = server.hash_password(new_password)

                self.cursor.execute(
                    "UPDATE users SET password_hash = ?, salt = ?, failed_attempts = 0, locked_until = NULL WHERE username = ?",
                    (password_hash, salt, self.username)
                )
                self.conn.commit()
                QMessageBox.information(self, "Success", "Password reset successfully")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to reset password: {e}")


class ServerWindow(QMainWindow):
    """Main server window with GUI controls"""

    def __init__(self):
        super().__init__()
        self.server = SecureServer()
        self.init_ui()
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(2000)

    def init_ui(self):
        self.setWindowTitle("Secure Messenger Server")
        self.setGeometry(100, 100, 1000, 700)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        header = QHBoxLayout()
        title = QLabel("Secure Messenger Server")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        header.addWidget(title)
        header.addStretch()

        self.start_btn = QPushButton("Start Server")
        self.start_btn.clicked.connect(self.start_server)
        header.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop Server")
        self.stop_btn.clicked.connect(self.stop_server)
        self.stop_btn.setEnabled(False)
        header.addWidget(self.stop_btn)

        main_layout.addLayout(header)

        status_layout = QHBoxLayout()
        self.server_status_label = QLabel("Server: Stopped")
        self.clients_label = QLabel("Connected: 0")
        status_layout.addWidget(self.server_status_label)
        status_layout.addWidget(self.clients_label)
        status_layout.addStretch()
        main_layout.addLayout(status_layout)

        tabs = QTabWidget()

        users_tab = QWidget()
        users_layout = QVBoxLayout(users_tab)

        search_layout = QHBoxLayout()
        self.user_search_input = QLineEdit()
        self.user_search_input.setPlaceholderText("Search users...")
        self.user_search_input.textChanged.connect(self.search_users)
        search_layout.addWidget(self.user_search_input)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.load_users)
        search_layout.addWidget(refresh_btn)

        users_layout.addLayout(search_layout)

        self.users_table = QTableWidget()
        self.users_table.setColumnCount(7)
        self.users_table.setHorizontalHeaderLabels([
            "ID", "Username", "Email", "Registration", "Last Login", "Avatar", "Actions"
        ])
        self.users_table.horizontalHeader().setStretchLastSection(True)
        self.users_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.users_table.itemDoubleClicked.connect(self.on_user_double_clicked)
        users_layout.addWidget(self.users_table)

        user_actions = QHBoxLayout()
        delete_selected_btn = QPushButton("Delete Selected")
        delete_selected_btn.clicked.connect(self.delete_selected_users)
        user_actions.addWidget(delete_selected_btn)
        user_actions.addStretch()
        users_layout.addLayout(user_actions)

        tabs.addTab(users_tab, "Users")

        stats_tab = QWidget()
        stats_layout = QVBoxLayout(stats_tab)

        self.total_users_label = QLabel("Total users: 0")
        self.online_users_label = QLabel("Online users: 0")
        self.total_messages_label = QLabel("Total messages: 0")
        self.total_files_label = QLabel("Total files: 0")
        self.pending_messages_label = QLabel("Pending delivery: 0")

        stats_layout.addWidget(self.total_users_label)
        stats_layout.addWidget(self.online_users_label)
        stats_layout.addWidget(self.total_messages_label)
        stats_layout.addWidget(self.total_files_label)
        stats_layout.addWidget(self.pending_messages_label)
        stats_layout.addStretch()

        tabs.addTab(stats_tab, "Statistics")

        broadcast_tab = QWidget()
        broadcast_layout = QVBoxLayout(broadcast_tab)

        broadcast_layout.addWidget(QLabel("Send Broadcast Message:"))

        broadcast_layout.addWidget(QLabel("Subject:"))
        self.broadcast_subject = QLineEdit()
        broadcast_layout.addWidget(self.broadcast_subject)

        broadcast_layout.addWidget(QLabel("Message:"))
        self.broadcast_message = QTextEdit()
        broadcast_layout.addWidget(self.broadcast_message)

        send_broadcast_btn = QPushButton("Send Broadcast")
        send_broadcast_btn.clicked.connect(self.send_broadcast)
        broadcast_layout.addWidget(send_broadcast_btn)

        tabs.addTab(broadcast_tab, "Broadcast")

        logs_tab = QWidget()
        logs_layout = QVBoxLayout(logs_tab)

        logs_actions = QHBoxLayout()
        clear_logs_btn = QPushButton("Clear Logs")
        clear_logs_btn.clicked.connect(self.clear_logs)
        logs_actions.addWidget(clear_logs_btn)

        save_logs_btn = QPushButton("Save Logs")
        save_logs_btn.clicked.connect(self.save_logs)
        logs_actions.addWidget(save_logs_btn)

        cleanup_btn = QPushButton("Run Cleanup Now")
        cleanup_btn.clicked.connect(self.run_cleanup_now)
        logs_actions.addWidget(cleanup_btn)

        logs_actions.addStretch()
        logs_layout.addLayout(logs_actions)

        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        logs_layout.addWidget(self.logs_text)

        tabs.addTab(logs_tab, "Logs")

        main_layout.addWidget(tabs)

        self.load_users()

    def start_server(self):
        """Start the server"""
        if self.server.start():
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.server_status_label.setText("Server: Running")
            self.log("Server started successfully")
            self.log(f"Message retention: {self.server.message_retention_hours} hours")
            self.log("Auto-cleanup enabled")
        else:
            self.log("Failed to start server")
            QMessageBox.critical(self, "Error", "Failed to start server")

    def stop_server(self):
        """Stop the server"""
        self.server.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.server_status_label.setText("Server: Stopped")
        self.log("Server stopped")

    def run_cleanup_now(self):
        """Run cleanup manually"""
        self.server.cleanup_old_messages()
        self.log("Manual cleanup completed")
        QMessageBox.information(self, "Cleanup", "Cleanup completed successfully")

    def load_users(self):
        """Load users from database into table"""
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

                edit_btn = QPushButton("Edit")
                edit_btn.clicked.connect(lambda checked, u=user[1]: self.edit_user(u))
                actions_layout.addWidget(edit_btn)

                delete_btn = QPushButton("Delete")
                delete_btn.clicked.connect(lambda checked, u=user[1]: self.delete_user(u))
                actions_layout.addWidget(delete_btn)

                actions_widget.setLayout(actions_layout)
                self.users_table.setCellWidget(row, 6, actions_widget)

                for col in range(6):
                    item = self.users_table.item(row, col)
                    if item:
                        item.setTextAlignment(Qt.AlignCenter)
        except Exception as e:
            self.log(f"Error loading users: {e}")

    def set_default_avatar_icon(self, avatar_item):
        """Set a default avatar icon"""
        pixmap = QPixmap(32, 32)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setBrush(QBrush(QColor(100, 150, 200)))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(1, 1, 30, 30)
        painter.end()
        avatar_item.setIcon(QIcon(pixmap))

    def on_user_double_clicked(self, item):
        """Handle double-click on user row"""
        row = item.row()
        username = self.users_table.item(row, 1).text()
        self.edit_user(username)

    def edit_user(self, username):
        """Open edit dialog for user"""
        dialog = UserEditDialog(username, self.server.cursor, self.server.conn, self)
        if dialog.exec_():
            self.load_users()

    def search_users(self):
        """Search users by username or email"""
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

                edit_btn = QPushButton("Edit")
                edit_btn.clicked.connect(lambda checked, u=user[1]: self.edit_user(u))
                actions_layout.addWidget(edit_btn)

                delete_btn = QPushButton("Delete")
                delete_btn.clicked.connect(lambda checked, u=user[1]: self.delete_user(u))
                actions_layout.addWidget(delete_btn)

                actions_widget.setLayout(actions_layout)
                self.users_table.setCellWidget(row, 6, actions_widget)

                for col in range(6):
                    item = self.users_table.item(row, col)
                    if item:
                        item.setTextAlignment(Qt.AlignCenter)
        except Exception as e:
            self.log(f"Error searching users: {e}")

    def delete_user(self, username):
        """Delete a user from the database"""
        reply = QMessageBox.question(
            self, 'Confirmation',
            f'Delete user {username} and all their messages?',
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            try:
                # Delete user's messages
                self.server.cursor.execute("DELETE FROM messages WHERE sender = ? OR receiver = ?",
                                           (username, username))
                # Delete user's files
                self.server.cursor.execute("DELETE FROM files WHERE sender = ? OR receiver = ?", (username, username))
                # Delete user
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
                self.log(f"User {username} deleted with all messages")
            except Exception as e:
                self.log(f"Error deleting user: {e}")

    def delete_selected_users(self):
        """Delete multiple selected users"""
        selected = self.users_table.selectionModel().selectedRows()
        if selected:
            reply = QMessageBox.question(
                self, 'Confirmation',
                f'Delete {len(selected)} selected user(s)?',
                QMessageBox.Yes | QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                for index in selected:
                    username = self.users_table.item(index.row(), 1).text()
                    self.delete_user(username)

    def send_broadcast(self):
        """Send broadcast message to all online users"""
        subject = self.broadcast_subject.text()
        message = self.broadcast_message.toPlainText()

        if not subject or not message:
            QMessageBox.warning(self, "Error", "Fill in subject and message")
            return

        sent_count = self.server.send_broadcast(subject, message)

        QMessageBox.information(
            self, "Broadcast",
            f"Message sent to {sent_count} user(s)"
        )
        self.broadcast_subject.clear()
        self.broadcast_message.clear()
        self.log(f"Broadcast sent: {subject} ({sent_count} users)")

    def update_stats(self):
        """Update statistics display"""
        try:
            self.server.cursor.execute("SELECT COUNT(*) FROM users")
            total_users = self.server.cursor.fetchone()[0]
            self.total_users_label.setText(f"Total users: {total_users}")

            with self.server.lock:
                online_users = len(self.server.clients)
                self.online_users_label.setText(f"Online users: {online_users}")
                self.clients_label.setText(f"Connected: {online_users}")

            self.server.cursor.execute("SELECT COUNT(*) FROM messages")
            total_messages = self.server.cursor.fetchone()[0]
            self.total_messages_label.setText(f"Total messages: {total_messages}")

            self.server.cursor.execute("SELECT COUNT(*) FROM files")
            total_files = self.server.cursor.fetchone()[0]
            self.total_files_label.setText(f"Total files: {total_files}")

            self.server.cursor.execute("SELECT COUNT(*) FROM messages WHERE delivered = 0")
            pending_messages = self.server.cursor.fetchone()[0]
            self.pending_messages_label.setText(f"Pending delivery: {pending_messages}")

        except Exception as e:
            print(f"Error updating stats: {e}")

    def log(self, message):
        """Add message to log display"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.logs_text.append(f"[{timestamp}] {message}")

    def clear_logs(self):
        """Clear log display"""
        self.logs_text.clear()

    def save_logs(self):
        """Save logs to file"""
        file_name, _ = QFileDialog.getSaveFileName(
            self, "Save Logs", "", "Text Files (*.txt)"
        )
        if file_name:
            try:
                with open(file_name, 'w', encoding='utf-8') as f:
                    f.write(self.logs_text.toPlainText())
                self.log(f"Logs saved to {file_name}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save logs: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    server = ServerWindow()
    server.show()
    sys.exit(app.exec_())