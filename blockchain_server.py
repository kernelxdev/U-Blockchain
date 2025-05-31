import socket
import threading
import json
import hashlib
import random
import string
import time
from datetime import datetime
import sqlite3
import uuid

class CryptoWalletServer:
    def __init__(self, host='0.0.0.0', port=8888, hash_length=6, mining_reward=3.25):
        self.host = host
        self.port = port
        self.hash_length = hash_length
        self.mining_reward = mining_reward  # Configurable reward amount
        self.current_target = None
        self.current_hash = None
        self.clients = []
        self.mining_active = True
        
        # Initialize database
        self.init_database()
        
        # Generate first hash
        self.generate_new_hash()
        
        # Start hash generation timer
        self.start_hash_timer()
    
    def init_database(self):
        """Initialize SQLite database with wallet system"""
        self.conn = sqlite3.connect('blockchain.db', check_same_thread=False)
        self.db_lock = threading.Lock()
        self.cursor = self.conn.cursor()
        
        # Create users table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                wallet_address TEXT UNIQUE NOT NULL,
                balance REAL DEFAULT 0.0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_login TEXT
            )
        ''')
        
        # Create transactions table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT UNIQUE NOT NULL,
                from_address TEXT,
                to_address TEXT NOT NULL,
                amount REAL NOT NULL,
                transaction_type TEXT NOT NULL,
                description TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                block_hash TEXT,
                ip_address TEXT
            )
        ''')
        
        # Create mining results table (updated with wallet info)
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS mining_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                wallet_address TEXT,
                ip_address TEXT,
                target_string TEXT,
                hash_value TEXT,
                reward_amount REAL,
                timestamp TEXT,
                attempts INTEGER
            )
        ''')
        
        # Create sessions table for authenticated connections
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS active_sessions (
                session_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                ip_address TEXT,
                login_time TEXT DEFAULT CURRENT_TIMESTAMP,
                last_activity TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.conn.commit()
        print("✅ Database initialized with wallet system")
    
    def generate_wallet_address(self):
        """Generate unique wallet address"""
        # Create a unique identifier and hash it
        unique_data = f"{uuid.uuid4()}{time.time()}{random.randint(1000, 9999)}"
        wallet_hash = hashlib.sha256(unique_data.encode()).hexdigest()
        return f"CRY{wallet_hash[:32].upper()}"  # 35 character wallet address
    
    def hash_password(self, password):
        """Hash password using SHA256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def create_user_account(self, username, password):
        """Create new user account"""
        with self.db_lock:
            try:
                # Check if username already exists
                self.cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
                if self.cursor.fetchone():
                    return {"success": False, "message": "Username already exists"}
                
                # Create new account
                password_hash = self.hash_password(password)
                wallet_address = self.generate_wallet_address()
                
                self.cursor.execute('''
                    INSERT INTO users (username, password_hash, wallet_address, balance)
                    VALUES (?, ?, ?, ?)
                ''', (username, password_hash, wallet_address, 0.0))
                
                self.conn.commit()
                
                print(f"🆕 New account created: {username} -> {wallet_address}")
                return {
                    "success": True, 
                    "message": "Account created successfully",
                    "wallet_address": wallet_address
                }
                
            except Exception as e:
                return {"success": False, "message": f"Database error: {str(e)}"}
    
    def authenticate_user(self, username, password, ip_address):
        """Authenticate user and create session"""
        with self.db_lock:
            try:
                password_hash = self.hash_password(password)
                
                self.cursor.execute('''
                    SELECT username, wallet_address, balance FROM users 
                    WHERE username = ? AND password_hash = ?
                ''', (username, password_hash))
                
                user = self.cursor.fetchone()
                if not user:
                    return {"success": False, "message": "Invalid username or password"}
                
                # Create session
                session_id = str(uuid.uuid4())
                self.cursor.execute('''
                    INSERT OR REPLACE INTO active_sessions (session_id, username, ip_address)
                    VALUES (?, ?, ?)
                ''', (session_id, username, ip_address))
                
                # Update last login
                self.cursor.execute('''
                    UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ?
                ''', (username,))
                
                self.conn.commit()
                
                print(f"🔐 User authenticated: {username} from {ip_address}")
                return {
                    "success": True,
                    "message": "Authentication successful",
                    "session_id": session_id,
                    "username": user[0],
                    "wallet_address": user[1],
                    "balance": user[2]
                }
                
            except Exception as e:
                return {"success": False, "message": f"Authentication error: {str(e)}"}
    
    def get_user_by_session(self, session_id):
        """Get user information by session ID"""
        with self.db_lock:
            try:
                self.cursor.execute('''
                    SELECT u.username, u.wallet_address, u.balance 
                    FROM users u 
                    JOIN active_sessions s ON u.username = s.username 
                    WHERE s.session_id = ?
                ''', (session_id,))
                
                result = self.cursor.fetchone()
                if result:
                    # Update last activity
                    self.cursor.execute('''
                        UPDATE active_sessions SET last_activity = CURRENT_TIMESTAMP 
                        WHERE session_id = ?
                    ''', (session_id,))
                    self.conn.commit()
                    
                    return {
                        "username": result[0],
                        "wallet_address": result[1],
                        "balance": result[2]
                    }
                return None
            except Exception as e:
                print(f"Session lookup error: {e}")
                return None
    
    def add_coins_to_wallet(self, username, amount, description="Mining reward"):
        """Add coins to user's wallet"""
        with self.db_lock:
            try:
                # Get user info
                self.cursor.execute("SELECT wallet_address, balance FROM users WHERE username = ?", (username,))
                user = self.cursor.fetchone()
                if not user:
                    return False
                
                wallet_address, current_balance = user
                new_balance = current_balance + amount
                
                # Update balance
                self.cursor.execute('''
                    UPDATE users SET balance = ? WHERE username = ?
                ''', (new_balance, username))
                
                # Record transaction
                transaction_id = str(uuid.uuid4())
                self.cursor.execute('''
                    INSERT INTO transactions 
                    (transaction_id, from_address, to_address, amount, transaction_type, description, block_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (transaction_id, "SYSTEM", wallet_address, amount, "MINING_REWARD", description, self.current_hash))
                
                self.conn.commit()
                
                print(f"💰 Added {amount} coins to {username}'s wallet (New balance: {new_balance})")
                return True
                
            except Exception as e:
                print(f"Error adding coins: {e}")
                return False
    
    def get_wallet_info(self, username):
        """Get complete wallet information"""
        with self.db_lock:
            try:
                # Get user info
                self.cursor.execute('''
                    SELECT username, wallet_address, balance, created_at, last_login 
                    FROM users WHERE username = ?
                ''', (username,))
                user = self.cursor.fetchone()
                
                if not user:
                    return None
                
                # Get recent transactions
                self.cursor.execute('''
                    SELECT transaction_id, from_address, to_address, amount, 
                           transaction_type, description, timestamp
                    FROM transactions 
                    WHERE to_address = (SELECT wallet_address FROM users WHERE username = ?)
                       OR from_address = (SELECT wallet_address FROM users WHERE username = ?)
                    ORDER BY timestamp DESC LIMIT 10
                ''', (username, username))
                
                transactions = []
                for tx in self.cursor.fetchall():
                    transactions.append({
                        "transaction_id": tx[0],
                        "from_address": tx[1],
                        "to_address": tx[2],
                        "amount": tx[3],
                        "type": tx[4],
                        "description": tx[5],
                        "timestamp": tx[6]
                    })
                
                return {
                    "username": user[0],
                    "wallet_address": user[1],
                    "balance": user[2],
                    "created_at": user[3],
                    "last_login": user[4],
                    "recent_transactions": transactions
                }
                
            except Exception as e:
                print(f"Error getting wallet info: {e}")
                return None
    
    def generate_random_string(self):
        """Generate random string of specified length"""
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(self.hash_length))
    
    def generate_new_hash(self):
        """Generate new target string and its hash"""
        self.current_target = self.generate_random_string()
        self.current_hash = hashlib.sha256(self.current_target.encode()).hexdigest()
        print(f"[{datetime.now()}] New hash generated!")
        print(f"Target: {self.current_target}")
        print(f"Hash: {self.current_hash}")
        print(f"Mining reward: {self.mining_reward} coins")
        print("-" * 50)
    
    def start_hash_timer(self):
        """Start timer to generate new hash every 4 hours"""
        def hash_timer():
            while True:
                time.sleep(4 * 60 * 60)  # 4 hours in seconds
                if self.mining_active:
                    old_hash = self.current_hash
                    self.generate_new_hash()
                    self.broadcast_new_hash(old_hash)
        
        timer_thread = threading.Thread(target=hash_timer, daemon=True)
        timer_thread.start()
    
    def broadcast_new_hash(self, old_hash=None):
        """Send new hash to all connected clients"""
        message = {
            'type': 'new_hash',
            'target_string': self.current_target,
            'hash': self.current_hash,
            'target_length': len(self.current_target),
            'mining_reward': self.mining_reward,
            'old_hash': old_hash,
            'timestamp': datetime.now().isoformat()
        }
        self.broadcast_message(message)
    
    def broadcast_message(self, message):
        """Send message to all connected clients"""
        dead_clients = []
        for client in self.clients:
            try:
                client.send(json.dumps(message).encode() + b'\n')
            except:
                dead_clients.append(client)
        
        # Remove dead connections
        for client in dead_clients:
            self.clients.remove(client)
    
    def handle_client(self, client_socket, address):
        """Handle individual client connection"""
        print(f"Client connected from {address}")
        self.clients.append(client_socket)
        
        # Send welcome message
        welcome_message = {
            'type': 'welcome',
            'message': 'Welcome to CryptoMiner with Wallet System!',
            'server_info': {
                'hash_length': self.hash_length,
                'mining_reward': self.mining_reward,
                'current_hash': self.current_hash,
                'target_length': len(self.current_target) if self.current_target else 0
            }
        }
        
        try:
            client_socket.send(json.dumps(welcome_message).encode() + b'\n')
        except:
            pass
        
        try:
            while True:
                data = client_socket.recv(4096)  # Increased buffer for auth messages
                if not data:
                    break
                
                try:
                    message = json.loads(data.decode().strip())
                    self.process_client_message(message, address[0], client_socket)
                except json.JSONDecodeError:
                    pass
                
        except:
            pass
        finally:
            if client_socket in self.clients:
                self.clients.remove(client_socket)
            client_socket.close()
            print(f"Client {address} disconnected")
    
    def process_client_message(self, message, ip_address, client_socket):
        """Process messages from clients"""
        msg_type = message.get('type')
        
        if msg_type == 'register':
            username = message.get('username')
            password = message.get('password')
            
            if not username or not password:
                response = {"success": False, "message": "Username and password required"}
            else:
                response = self.create_user_account(username, password)
            
            self.send_response(client_socket, 'register_response', response)
            
        elif msg_type == 'login':
            username = message.get('username')
            password = message.get('password')
            
            if not username or not password:
                response = {"success": False, "message": "Username and password required"}
            else:
                response = self.authenticate_user(username, password, ip_address)
            
            self.send_response(client_socket, 'login_response', response)
            
        elif msg_type == 'get_current_hash':
            session_id = message.get('session_id')
            user = self.get_user_by_session(session_id)
            
            if user:
                hash_info = {
                    'type': 'current_hash',
                    'target_string': self.current_target,
                    'hash': self.current_hash,
                    'target_length': len(self.current_target),
                    'mining_reward': self.mining_reward,
                    'timestamp': datetime.now().isoformat()
                }
                self.send_response(client_socket, 'current_hash', hash_info)
            else:
                self.send_response(client_socket, 'error', {"message": "Invalid session"})
                
        elif msg_type == 'solution_found':
            session_id = message.get('session_id')
            user = self.get_user_by_session(session_id)
            
            if not user:
                self.send_response(client_socket, 'error', {"message": "Invalid session"})
                return
            
            guessed_string = message.get('solution')
            attempts = message.get('attempts', 0)
            
            # Verify the solution
            if self.verify_solution(guessed_string):
                print(f"🎉 SOLUTION FOUND by {user['username']} ({ip_address})!")
                print(f"Solution: {guessed_string}")
                print(f"Attempts: {attempts}")
                
                # Add reward to user's wallet
                reward_added = self.add_coins_to_wallet(
                    user['username'], 
                    self.mining_reward, 
                    f"Mining reward for hash {self.current_hash[:16]}..."
                )
                
                if reward_added:
                    # Record mining result
                    self.record_mining_result(user, ip_address, guessed_string, attempts)
                    
                    # Generate new hash
                    old_hash = self.current_hash
                    self.generate_new_hash()
                    
                    # Get updated balance
                    updated_user = self.get_user_by_session(session_id)
                    
                    # Notify all clients
                    success_message = {
                        'type': 'solution_accepted',
                        'solver_username': user['username'],
                        'solver_wallet': user['wallet_address'],
                        'solution': guessed_string,
                        'attempts': attempts,
                        'reward_amount': self.mining_reward,
                        'new_target_string': self.current_target,
                        'new_hash': self.current_hash,
                        'target_length': len(self.current_target),
                        'timestamp': datetime.now().isoformat()
                    }
                    self.broadcast_message(success_message)
                    
                    # Send personal success message
                    personal_message = {
                        'type': 'mining_success',
                        'reward': self.mining_reward,
                        'new_balance': updated_user['balance'] if updated_user else 0,
                        'message': f'Congratulations! You earned {self.mining_reward} coins!'
                    }
                    self.send_response(client_socket, 'mining_success', personal_message)
                    
        elif msg_type == 'get_wallet_info':
            session_id = message.get('session_id')
            user = self.get_user_by_session(session_id)
            
            if user:
                wallet_info = self.get_wallet_info(user['username'])
                self.send_response(client_socket, 'wallet_info', wallet_info)
            else:
                self.send_response(client_socket, 'error', {"message": "Invalid session"})
    
    def send_response(self, client_socket, response_type, data):
        """Send response to specific client"""
        try:
            response = {
                'type': response_type,
                'data': data,
                'timestamp': datetime.now().isoformat()
            }
            client_socket.send(json.dumps(response).encode() + b'\n')
        except Exception as e:
            print(f"Error sending response: {e}")
    
    def verify_solution(self, guessed_string):
        """Verify if the guessed string produces the current hash"""
        if not guessed_string:
            return False
        guessed_hash = hashlib.sha256(guessed_string.encode()).hexdigest()
        return guessed_hash == self.current_hash
    
    def record_mining_result(self, user, ip_address, target_string, attempts):
        """Record successful mining result"""
        with self.db_lock:
            try:
                self.cursor.execute('''
                    INSERT INTO mining_results 
                    (username, wallet_address, ip_address, target_string, hash_value, reward_amount, timestamp, attempts)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (user['username'], user['wallet_address'], ip_address, target_string, 
                      self.current_hash, self.mining_reward, datetime.now().isoformat(), attempts))
                self.conn.commit()
            except Exception as e:
                print(f"Database error recording mining result: {e}")
    
    def start_server(self):
        """Start the server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        print(f"🚀 Crypto Mining Server with Wallet System started on {self.host}:{self.port}")
        print(f"💰 Mining reward: {self.mining_reward} coins per solution")
        print(f"🔍 Hash length: {self.hash_length} characters")
        print(f"⏰ New hash every 4 hours")
        print("=" * 60)
        
        try:
            while True:
                client_socket, address = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()
        except KeyboardInterrupt:
            print("\nShutting down server...")
        finally:
            server_socket.close()
            self.conn.close()

def main():
    # Configuration
    HOST = '0.0.0.0'  # Listen on all interfaces
    PORT = 598
    HASH_LENGTH = 5   # Difficulty level
    MINING_REWARD = 3.25  # Coins rewarded per successful mine
    
    print("🏗️  Starting Crypto Mining Server with Wallet System...")
    print(f"Configuration:")
    print(f"  Host: {HOST}")
    print(f"  Port: {PORT}")
    print(f"  Hash Length: {HASH_LENGTH}")
    print(f"  Mining Reward: {MINING_REWARD} coins")
    print()
    
    server = CryptoWalletServer(HOST, PORT, HASH_LENGTH, MINING_REWARD)
    server.start_server()

if __name__ == "__main__":
    main()