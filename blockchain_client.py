#!/usr/bin/env python3
"""
Complete Crypto Wallet Client for CryptoServer
Features:
- User registration and login
- Wallet management and balance checking
- Mining with real-time progress
- Sending/receiving transactions
- Transaction history viewing
- Network statistics
- Session management
- Auto-reconnection
"""

import socket
import json
import threading
import hashlib
import random
import string
import time
from datetime import datetime
import os
import sys

class CryptoWalletClient:
    def __init__(self, host='localhost', port=598):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.session_id = None
        self.username = None
        self.wallet_address = None
        self.balance = 0.0
        
        # Mining variables
        self.mining_active = False
        self.current_target = None
        self.current_hash = None
        self.target_length = 0
        self.mining_reward = 0.0
        self.mining_thread = None
        self.attempts = 0
        self.start_time = None
        
        # Message handling
        self.message_handlers = {
            'welcome': self.handle_welcome,
            'new_hash': self.handle_new_hash,
            'solution_accepted': self.handle_solution_accepted,
            'register_response': self.handle_register_response,
            'login_response': self.handle_login_response,
            'wallet_info': self.handle_wallet_info,
            'balance_response': self.handle_balance_response,
            'transaction_response': self.handle_transaction_response,
            'transaction_history': self.handle_transaction_history,
            'network_status': self.handle_network_status,
            'mining_success': self.handle_mining_success,
            'error': self.handle_error
        }
        
        self.listener_thread = None
        self.running = True
    
    def connect(self):
        """Connect to the crypto server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((self.host, self.port))
            self.connected = True
            
            # Start message listener
            self.listener_thread = threading.Thread(target=self.listen_for_messages, daemon=True)
            self.listener_thread.start()
            
            print(f"✅ Connected to crypto server at {self.host}:{self.port}")
            return True
            
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from server"""
        self.running = False
        self.stop_mining()
        
        if self.session_id:
            self.send_message({
                'type': 'logout',
                'session_id': self.session_id
            })
        
        if self.socket:
            self.socket.close()
        
        self.connected = False
        self.session_id = None
        print("👋 Disconnected from server")
    
    def send_message(self, message):
        """Send message to server"""
        if not self.connected or not self.socket:
            print("❌ Not connected to server")
            return False
        
        try:
            message_json = json.dumps(message) + '\n'
            self.socket.send(message_json.encode())
            return True
        except Exception as e:
            print(f"❌ Failed to send message: {e}")
            return False
    
    def listen_for_messages(self):
        """Listen for incoming messages from server"""
        buffer = ""
        
        while self.running and self.connected:
            try:
                data = self.socket.recv(4096)
                if not data:
                    break
                
                buffer += data.decode()
                
                # Process complete messages (separated by newlines)
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    if line.strip():
                        try:
                            message = json.loads(line.strip())
                            self.handle_message(message)
                        except json.JSONDecodeError:
                            pass
                        
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"⚠️ Connection lost: {e}")
                break
        
        self.connected = False
    
    def handle_message(self, message):
        """Handle incoming message from server"""
        msg_type = message.get('type')
        handler = self.message_handlers.get(msg_type)
        
        if handler:
            handler(message)
        else:
            print(f"⚠️ Unknown message type: {msg_type}")
    
    def handle_welcome(self, message):
        """Handle welcome message from server"""
        data = message.get('data', {})
        server_info = data.get('server_info', {})
        
        self.mining_reward = server_info.get('mining_reward', 0)
        self.current_hash = server_info.get('current_hash')
        self.current_target = server_info.get('target_string')
        
        print(f"🎉 {data.get('message', 'Welcome!')}")
        print(f"💰 Mining reward: {self.mining_reward} coins")
        if self.current_target:
            print(f"🎯 Current target: {self.current_target}")
    
    def handle_new_hash(self, message):
        """Handle new mining challenge"""
        self.current_target = message.get('target_string')
        self.current_hash = message.get('hash')
        self.target_length = message.get('target_length', 0)
        self.mining_reward = message.get('mining_reward', 0)
        
        print(f"\n🆕 New mining challenge!")
        print(f"🎯 Target: {self.current_target}")
        print(f"💰 Reward: {self.mining_reward} coins")
        
        # Reset mining stats
        self.attempts = 0
        if self.mining_active:
            print("⛏️ Mining automatically restarted...")
    
    def handle_solution_accepted(self, message):
        """Handle solution acceptance broadcast"""
        solver = message.get('solver_username')
        reward = message.get('reward_amount', 0)
        solution = message.get('solution')
        
        if solver == self.username:
            print(f"\n🎉 YOUR SOLUTION WAS ACCEPTED!")
        else:
            print(f"\n🏆 {solver} found the solution: '{solution}'")
        
        print(f"💰 Reward: {reward} coins")
        print("🆕 New challenge started...")
    
    def handle_register_response(self, message):
        """Handle registration response"""
        data = message.get('data', {})
        if data.get('success'):
            print(f"✅ {data.get('message')}")
            if 'wallet_address' in data:
                print(f"💳 Your wallet address: {data['wallet_address']}")
        else:
            print(f"❌ Registration failed: {data.get('message')}")
    
    def handle_login_response(self, message):
        """Handle login response"""
        data = message.get('data', {})
        if data.get('success'):
            self.session_id = data.get('session_id')
            self.username = data.get('username')
            self.wallet_address = data.get('wallet_address')
            self.balance = data.get('balance', 0.0)
            
            print(f"✅ Login successful!")
            print(f"👤 Username: {self.username}")
            print(f"💳 Wallet: {self.wallet_address}")
            print(f"💰 Balance: {self.balance:.6f} coins")
        else:
            print(f"❌ Login failed: {data.get('message')}")
    
    def handle_wallet_info(self, message):
        """Handle wallet information"""
        data = message.get('data', {})
        if 'username' in data:
            print(f"\n💳 Wallet Information")
            print(f"👤 Username: {data['username']}")
            print(f"💳 Address: {data['wallet_address']}")
            print(f"💰 Balance: {data['balance']:.6f} coins")
            print(f"📅 Created: {data.get('created_at', 'Unknown')}")
            print(f"🔄 Transactions: {data.get('transaction_count', 0)}")
            
            # Show recent transactions
            recent_txs = data.get('recent_transactions', [])
            if recent_txs:
                print(f"\n📜 Recent Transactions:")
                for tx in recent_txs[:5]:
                    tx_type = tx.get('type', 'TRANSFER')
                    amount = tx.get('amount', 0)
                    timestamp = tx.get('timestamp', '')[:19]  # Remove microseconds
                    
                    if tx_type == 'BONUS':
                        print(f"  💝 +{amount:.6f} - {tx.get('message', 'Bonus')} ({timestamp})")
                    elif tx_type == 'MINING_REWARD':
                        print(f"  ⛏️ +{amount:.6f} - Mining reward ({timestamp})")
                    elif tx.get('from_address') == self.wallet_address:
                        to_addr = tx.get('to_address', '')[-8:]  # Last 8 chars
                        print(f"  📤 -{amount:.6f} - Sent to ...{to_addr} ({timestamp})")
                    else:
                        from_addr = tx.get('from_address', 'System')
                        if from_addr != 'System':
                            from_addr = f"...{from_addr[-8:]}"
                        print(f"  📥 +{amount:.6f} - From {from_addr} ({timestamp})")
        else:
            print("❌ Failed to get wallet information")
    
    def handle_balance_response(self, message):
        """Handle balance response"""
        data = message.get('data', {})
        if data.get('success'):
            self.balance = data.get('balance', 0.0)
            print(f"💰 Current balance: {self.balance:.6f} coins")
        else:
            print(f"❌ Failed to get balance: {data.get('message')}")
    
    def handle_transaction_response(self, message):
        """Handle transaction response"""
        data = message.get('data', {})
        if data.get('success'):
            print(f"✅ {data.get('message')}")
            if 'transaction_id' in data:
                print(f"📝 Transaction ID: {data['transaction_id']}")
            if 'new_balance' in data:
                self.balance = data['new_balance']
                print(f"💰 New balance: {self.balance:.6f} coins")
        else:
            print(f"❌ Transaction failed: {data.get('message')}")
    
    def handle_transaction_history(self, message):
        """Handle transaction history"""
        data = message.get('data', {})
        if data.get('success'):
            transactions = data.get('transactions', [])
            if transactions:
                print(f"\n📜 Transaction History ({len(transactions)} transactions)")
                print("-" * 80)
                for tx in transactions:
                    tx_id = tx.get('transaction_id', '')[:16]
                    tx_type = tx.get('type', 'TRANSFER')
                    amount = tx.get('amount', 0)
                    fee = tx.get('fee', 0)
                    timestamp = tx.get('timestamp', '')[:19]
                    message_text = tx.get('message', '')
                    
                    # Determine direction
                    if tx_type in ['BONUS', 'MINING_REWARD']:
                        direction = "📥 IN "
                        color_amount = f"+{amount:.6f}"
                        other_party = tx.get('from_address', 'System')
                        if other_party != 'System':
                            other_party = f"...{other_party[-8:]}"
                    elif tx.get('from_address') == self.wallet_address:
                        direction = "📤 OUT"
                        color_amount = f"-{amount:.6f}"
                        other_party = f"...{tx.get('to_address', '')[-8:]}"
                        if fee > 0:
                            color_amount += f" (fee: {fee:.6f})"
                    else:
                        direction = "📥 IN "
                        color_amount = f"+{amount:.6f}"
                        other_party = f"...{tx.get('from_address', '')[-8:]}"
                    
                    print(f"{direction} {color_amount:>15} | {other_party:>12} | {timestamp}")
                    if message_text:
                        print(f"     💬 {message_text}")
                    print(f"     🔑 {tx_id}")
                    print()
            else:
                print("📜 No transactions found")
        else:
            print(f"❌ Failed to get transaction history: {data.get('message')}")
    
    def handle_network_status(self, message):
        """Handle network status information"""
        data = message.get('data', {})
        print(f"\n🌐 Network Status")
        print(f"👥 Active users: {data.get('active_users', 0)}")
        print(f"⛏️ Active miners: {data.get('active_miners', 0)}")
        print(f"💰 Total coins mined: {data.get('total_coins_mined', 0):.6f}")
        print(f"📊 Daily transactions: {data.get('daily_transactions', 0)}")
        if 'current_challenge' in data:
            challenge = data['current_challenge']
            print(f"🎯 Current challenge: {challenge.get('target', 'N/A')}")
            print(f"💰 Mining reward: {challenge.get('reward', 0)} coins")
    
    def handle_mining_success(self, message):
        """Handle personal mining success"""
        data = message.get('data', {})
        reward = data.get('reward', 0)
        new_balance = data.get('new_balance', 0)
        
        print(f"\n🎉 MINING SUCCESS!")
        print(f"💰 Reward earned: {reward} coins")
        print(f"💳 New balance: {new_balance:.6f} coins")
        self.balance = new_balance
    
    def handle_error(self, message):
        """Handle error message"""
        data = message.get('data', {})
        print(f"❌ Error: {data.get('message', 'Unknown error')}")
    
    # User Authentication Methods
    def register_account(self, username, password):
        """Register new account"""
        if not self.connected:
            print("❌ Not connected to server")
            return
        
        message = {
            'type': 'register',
            'username': username,
            'password': password
        }
        self.send_message(message)
    
    def login(self, username, password):
        """Login to account"""
        if not self.connected:
            print("❌ Not connected to server")
            return
        
        message = {
            'type': 'login',
            'username': username,
            'password': password
        }
        self.send_message(message)
    
    def logout(self):
        """Logout from account"""
        if self.session_id:
            message = {
                'type': 'logout',
                'session_id': self.session_id
            }
            self.send_message(message)
            self.session_id = None
            self.username = None
            self.wallet_address = None
            self.balance = 0.0
            print("👋 Logged out successfully")
        else:
            print("⚠️ Not logged in")
    
    # Wallet Methods
    def get_wallet_info(self):
        """Get complete wallet information"""
        if not self.session_id:
            print("❌ Please login first")
            return
        
        message = {
            'type': 'get_wallet_info',
            'session_id': self.session_id
        }
        self.send_message(message)
    
    def get_balance(self):
        """Get current balance"""
        if not self.session_id:
            print("❌ Please login first")
            return
        
        message = {
            'type': 'get_balance',
            'session_id': self.session_id
        }
        self.send_message(message)
    
    def send_coins(self, to_address, amount, message_text="", fee=0.001):
        """Send coins to another wallet"""
        if not self.session_id:
            print("❌ Please login first")
            return
        
        try:
            amount = float(amount)
            fee = float(fee)
        except ValueError:
            print("❌ Invalid amount or fee")
            return
        
        if amount <= 0:
            print("❌ Amount must be positive")
            return
        
        message = {
            'type': 'send_transaction',
            'session_id': self.session_id,
            'to_address': to_address.strip(),
            'amount': amount,
            'message': message_text,
            'fee': fee
        }
        self.send_message(message)
    
    def get_transaction_history(self, limit=50):
        """Get transaction history"""
        if not self.session_id:
            print("❌ Please login first")
            return
        
        message = {
            'type': 'get_transaction_history',
            'session_id': self.session_id,
            'limit': min(limit, 100)
        }
        self.send_message(message)
    
    def get_network_status(self):
        """Get network statistics"""
        message = {
            'type': 'get_network_status'
        }
        self.send_message(message)
    
    # Mining Methods
    def start_mining(self):
        """Start mining process"""
        if not self.session_id:
            print("❌ Please login to start mining")
            return
        
        if not self.current_target or not self.current_hash:
            print("❌ No mining challenge available")
            return
        
        if self.mining_active:
            print("⚠️ Mining already active")
            return
        
        self.mining_active = True
        self.attempts = 0
        self.start_time = time.time()
        
        print(f"⛏️ Starting mining...")
        print(f"🎯 Target: {self.current_target}")
        print(f"💰 Reward: {self.mining_reward} coins")
        
        self.mining_thread = threading.Thread(target=self.mining_worker, daemon=True)
        self.mining_thread.start()
    
    def stop_mining(self):
        """Stop mining process"""
        if self.mining_active:
            self.mining_active = False
            print("⛔ Mining stopped")
        else:
            print("⚠️ Mining not active")
    
    def mining_worker(self):
        """Mining worker thread"""
        characters = string.ascii_letters + string.digits
        last_report = time.time()
        
        while self.mining_active and self.current_hash:
            # Generate random string of correct length
            guess = ''.join(random.choice(characters) for _ in range(self.target_length))
            guess_hash = hashlib.sha256(guess.encode()).hexdigest()
            self.attempts += 1
            
            # Check if we found the solution
            if guess_hash == self.current_hash:
                print(f"\n🎉 SOLUTION FOUND!")
                print(f"💡 Solution: {guess}")
                print(f"🔄 Attempts: {self.attempts}")
                
                # Submit solution
                message = {
                    'type': 'solution_found',
                    'session_id': self.session_id,
                    'solution': guess,
                    'attempts': self.attempts
                }
                self.send_message(message)
                
                self.mining_active = False
                break
            
            # Progress report every 10 seconds
            if time.time() - last_report >= 10:
                elapsed = time.time() - self.start_time
                rate = self.attempts / elapsed if elapsed > 0 else 0
                print(f"⛏️ Mining... {self.attempts:,} attempts ({rate:.0f}/sec)")
                last_report = time.time()
            
            # Small delay to prevent excessive CPU usage
            if self.attempts % 10000 == 0:
                time.sleep(0.001)
    
    # Interactive CLI Methods
    def show_menu(self):
        """Show main menu"""
        print("\n" + "="*60)
        print("🏦 CRYPTO WALLET CLIENT")
        if self.username:
            print(f"👤 Logged in as: {self.username}")
            print(f"💰 Balance: {self.balance:.6f} coins")
        print("="*60)
        
        if not self.session_id:
            print("1. Register new account")
            print("2. Login to existing account")
        else:
            print("3. View wallet information")
            print("4. Check balance")
            print("5. Send coins")
            print("6. View transaction history")
            print("7. Start mining")
            print("8. Stop mining")
            print("9. Network status")
            print("10. Logout")
        
        print("0. Exit")
        print("-" * 60)
    
    def run_interactive(self):
        """Run interactive command line interface"""
        print("🚀 Starting Crypto Wallet Client...")
        
        if not self.connect():
            return
        
        try:
            while self.running and self.connected:
                self.show_menu()
                
                try:
                    choice = input("Select option: ").strip()
                    
                    if choice == '0':
                        break
                    elif choice == '1' and not self.session_id:
                        username = input("Username: ").strip()
                        password = input("Password: ").strip()
                        if username and password:
                            self.register_account(username, password)
                    elif choice == '2' and not self.session_id:
                        username = input("Username: ").strip()
                        password = input("Password: ").strip()
                        if username and password:
                            self.login(username, password)
                    elif choice == '3' and self.session_id:
                        self.get_wallet_info()
                    elif choice == '4' and self.session_id:
                        self.get_balance()
                    elif choice == '5' and self.session_id:
                        to_address = input("Recipient address: ").strip()
                        amount = input("Amount: ").strip()
                        message_text = input("Message (optional): ").strip()
                        fee = input(f"Fee (default 0.001): ").strip() or "0.001"
                        if to_address and amount:
                            self.send_coins(to_address, amount, message_text, fee)
                    elif choice == '6' and self.session_id:
                        limit = input("Number of transactions (default 50): ").strip() or "50"
                        try:
                            limit = int(limit)
                            self.get_transaction_history(limit)
                        except ValueError:
                            print("❌ Invalid number")
                    elif choice == '7' and self.session_id:
                        self.start_mining()
                    elif choice == '8' and self.session_id:
                        self.stop_mining()
                    elif choice == '9':
                        self.get_network_status()
                    elif choice == '10' and self.session_id:
                        self.logout()
                    else:
                        print("❌ Invalid option or you need to login first")
                    
                    # Wait a moment for server response
                    time.sleep(0.5)
                    
                except KeyboardInterrupt:
                    break
                except EOFError:
                    break
                    
        except KeyboardInterrupt:
            pass
        finally:
            self.disconnect()

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Crypto Wallet Client')
    parser.add_argument('--host', default='localhost', help='Server host (default: localhost)')
    parser.add_argument('--port', type=int, default=598, help='Server port (default: 598)')
    args = parser.parse_args()
    
    client = CryptoWalletClient(args.host, args.port)
    client.run_interactive()

if __name__ == "__main__":
    main()