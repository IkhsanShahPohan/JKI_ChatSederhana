from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os 
import json
import threading
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
from flask_login import login_user, UserMixin, LoginManager, login_required, current_user, logout_user
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# JSON file paths
DATA_DIR = 'data'
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
ROOMS_FILE = os.path.join(DATA_DIR, 'rooms.json')
ROOM_MEMBERS_FILE = os.path.join(DATA_DIR, 'room_members.json')
MESSAGES_FILE = os.path.join(DATA_DIR, 'messages.json')

# Thread lock untuk thread-safe operations
data_lock = threading.Lock()

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# Initialize JSON files if they don't exist
def init_json_files():
    files = {
        USERS_FILE: [],
        ROOMS_FILE: [],
        ROOM_MEMBERS_FILE: [],
        MESSAGES_FILE: []
    }
    
    for file_path, default_data in files.items():
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                json.dump(default_data, f, indent=2)

# Helper functions for JSON operations
def load_json(file_path):
    with data_lock:
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

def save_json(file_path, data):
    with data_lock:
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

def get_next_id(data_list):
    """Get next available ID for a list of objects"""
    if not data_list:
        return 1
    return max(item['id'] for item in data_list) + 1

# User class untuk Flask-Login
class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['id']
        self.username = user_data['username']
        self.password_hash = user_data['password_hash']
        self._is_active = user_data.get('is_active', True)
    
    @property
    def is_active(self):
        return self._is_active
    
    @staticmethod
    def get(user_id):
        users = load_json(USERS_FILE)
        user_data = next((u for u in users if u['id'] == int(user_id)), None)
        return User(user_data) if user_data else None
    
    @staticmethod
    def get_by_username(username):
        users = load_json(USERS_FILE)
        user_data = next((u for u in users if u['username'] == username), None)
        return User(user_data) if user_data else None
    
    @staticmethod
    def create(username, password):
        users = load_json(USERS_FILE)
        
        # Check if user already exists
        if any(u['username'] == username for u in users):
            return None
        
        new_user = {
            'id': get_next_id(users),
            'username': username,
            'password_hash': generate_password_hash(password),
            'is_active': True,
            'created_at': datetime.now().isoformat()
        }
        
        users.append(new_user)
        save_json(USERS_FILE, users)
        return User(new_user)
    
    @staticmethod
    def get_all_except(user_id):
        users = load_json(USERS_FILE)
        return [User(u) for u in users if u['id'] != user_id]
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Room operations
class RoomManager:
    @staticmethod
    def get_all():
        rooms = load_json(ROOMS_FILE)
        return sorted(rooms, key=lambda x: x['created_at'], reverse=True)
    
    @staticmethod
    def get_by_id(room_id):
        rooms = load_json(ROOMS_FILE)
        return next((r for r in rooms if r['id'] == room_id), None)
    
    @staticmethod
    def get_by_name(name):
        rooms = load_json(ROOMS_FILE)
        return next((r for r in rooms if r['name'] == name), None)
    
    @staticmethod
    def create(name):
        rooms = load_json(ROOMS_FILE)
        
        # Check if room already exists
        if any(r['name'] == name for r in rooms):
            return next(r for r in rooms if r['name'] == name)
        
        new_room = {
            'id': get_next_id(rooms),
            'name': name,
            'created_at': datetime.now().isoformat()
        }
        
        rooms.append(new_room)
        save_json(ROOMS_FILE, rooms)
        return new_room
    
    @staticmethod
    def delete(room_id):
        # Delete room
        rooms = load_json(ROOMS_FILE)
        rooms = [r for r in rooms if r['id'] != room_id]
        save_json(ROOMS_FILE, rooms)
        
        # Delete room members
        members = load_json(ROOM_MEMBERS_FILE)
        members = [m for m in members if m['room_id'] != room_id]
        save_json(ROOM_MEMBERS_FILE, members)
        
        # Delete room messages
        messages = load_json(MESSAGES_FILE)
        messages = [m for m in messages if m.get('room_id') != room_id]
        save_json(MESSAGES_FILE, messages)

# Room Member operations
class RoomMemberManager:
    @staticmethod
    def add_member(user_id, room_id):
        members = load_json(ROOM_MEMBERS_FILE)
        
        # Check if already a member
        if any(m['user_id'] == user_id and m['room_id'] == room_id for m in members):
            return
        
        new_member = {
            'id': get_next_id(members),
            'user_id': user_id,
            'room_id': room_id,
            'joined_at': datetime.now().isoformat()
        }
        
        members.append(new_member)
        save_json(ROOM_MEMBERS_FILE, members)
    
    @staticmethod
    def is_member(user_id, room_id):
        members = load_json(ROOM_MEMBERS_FILE)
        return any(m['user_id'] == user_id and m['room_id'] == room_id for m in members)
    
    @staticmethod
    def get_user_rooms(user_id):
        members = load_json(ROOM_MEMBERS_FILE)
        return [m['room_id'] for m in members if m['user_id'] == user_id]

# Message operations
class MessageManager:
    @staticmethod
    def create_private_message(sender_id, receiver_id, algorithm, encrypted_message):
        messages = load_json(MESSAGES_FILE)
        
        new_message = {
            'id': get_next_id(messages),
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'room_id': None,
            'algorithm': algorithm,
            'encrypted': encrypted_message,
            'decrypted': None,
            'timestamp': datetime.now().isoformat()
        }
        
        messages.append(new_message)
        save_json(MESSAGES_FILE, messages)
        return new_message
    
    @staticmethod
    def create_room_message(sender_id, room_id, algorithm, encrypted_message):
        messages = load_json(MESSAGES_FILE)
        
        new_message = {
            'id': get_next_id(messages),
            'sender_id': sender_id,
            'receiver_id': None,
            'room_id': room_id,
            'algorithm': algorithm,
            'encrypted': encrypted_message,
            'decrypted': None,
            'timestamp': datetime.now().isoformat()
        }
        
        messages.append(new_message)
        save_json(MESSAGES_FILE, messages)
        return new_message
    
    @staticmethod
    def get_private_messages(user1_id, user2_id):
        messages = load_json(MESSAGES_FILE)
        return [m for m in messages if 
                (m['sender_id'] == user1_id and m['receiver_id'] == user2_id) or
                (m['sender_id'] == user2_id and m['receiver_id'] == user1_id)]
    
    @staticmethod
    def get_room_messages(room_id):
        messages = load_json(MESSAGES_FILE)
        return [m for m in messages if m.get('room_id') == room_id]
    
    @staticmethod
    def clear_private_messages(user1_id, user2_id):
        messages = load_json(MESSAGES_FILE)
        messages = [m for m in messages if not (
            (m['sender_id'] == user1_id and m['receiver_id'] == user2_id) or
            (m['sender_id'] == user2_id and m['receiver_id'] == user1_id)
        )]
        save_json(MESSAGES_FILE, messages)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Initialize JSON files
init_json_files()

# Fungsi untuk mengenkripsi pesan dengan AES
def encrypt_message_aes(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

# Fungsi untuk mendekripsi pesan dengan AES
def decrypt_message_aes(encrypted_message, key):
    try:
        data = base64.b64decode(encrypted_message.encode())
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except Exception as e:
        return f"[DECRYPTION FAILED: {e}]"

# Fungsi hash sederhana untuk warna avatar konsisten per user
AVATAR_COLOR_COUNT = 6

def get_avatar_color_idx(username):
    return abs(hash(username)) % AVATAR_COLOR_COUNT

# Halaman utama
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('chat'))
    return render_template('login.html')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.get_by_username(email)
        if user and user.check_password(password):
            login_user(user)
            session['username'] = user.username
            session['user_id'] = user.id
            return redirect(url_for('rooms'))
        else:
            error = 'Email atau kata sandi tidak valid.'
            return render_template('login.html', error=error)
    return render_template('login.html')

# Halaman chat
@app.route('/chat', defaults={'receiver_id': None}, methods=['GET', 'POST'])
@app.route('/chat/<int:receiver_id>', methods=['GET', 'POST'])
@login_required
def chat(receiver_id):
    AES_GLOBAL_KEY = os.getenv('AES_KEY', 'SixteenByteKey16').encode() # 16-byte key

    # Fitur clear chat (POST agar lebih aman)
    if request.method == 'POST' and request.form.get('clear_chat') == '1':
        if receiver_id:
            # Clear chat for a specific receiver
            MessageManager.clear_private_messages(current_user.id, receiver_id)
            # If clear chat is successful, return a success JSON response if it's an AJAX request
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': 'Chat history cleared successfully.'})
            return redirect(url_for('chat', receiver_id=receiver_id))
        else:
            # Handle case where no receiver is selected for clear chat
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': 'No receiver selected to clear chat history.'}), 400
            # Optional: redirect to chat page without receiver selected
            return redirect(url_for('chat'))

    encrypted_message = None
    decrypted_message = None
    receiver_username = None
    selected_receiver_user = None

    # Jika ada receiver_id yang dipilih, ambil username-nya
    if receiver_id:
        # Tambahan: Cegah chat dengan diri sendiri
        if receiver_id == current_user.id:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': 'Tidak bisa chat dengan diri sendiri.'}), 400
            receiver_id = None
        else:
            selected_receiver_user = User.get(receiver_id)
            if selected_receiver_user:
                receiver_username = selected_receiver_user.username
            else:
                # Jika receiver_id tidak valid, reset ke None
                receiver_id = None
                # Optionally, return an error if it's an AJAX request to load chat history
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'error': 'ID penerima tidak valid.'}), 400

    if request.method == 'POST' and request.form.get('clear_chat') != '1':
        # Menggunakan request.get_json() karena frontend mengirim sebagai application/json
        data = request.get_json()
        message = data.get('message')
        # Pastikan receiver_id diambil dari data JSON, yang harusnya cocok dengan yang aktif di frontend
        posted_receiver_id = data.get('receiver_id')

        if not message or message.strip() == '':
            return jsonify({'error': 'Pesan tidak boleh kosong. Silakan isi pesan.'}), 400

        if not posted_receiver_id:
            return jsonify({'error': 'Pilih penerima terlebih dahulu.'}), 400

        try:
            posted_receiver_id = int(posted_receiver_id) # Pastikan receiver_id adalah integer
            # Validasi bahwa posted_receiver_id adalah user yang valid
            if not User.get(posted_receiver_id):
                raise ValueError("Invalid receiver ID")
        except (ValueError, TypeError):
            return jsonify({'error': 'ID penerima tidak valid atau tidak ada.'}), 400

        # Gunakan posted_receiver_id untuk menyimpan pesan
        target_receiver_id = posted_receiver_id

        encrypted_message = encrypt_message_aes(message, AES_GLOBAL_KEY)

        # Simpan ke JSON
        MessageManager.create_private_message(
            sender_id=current_user.id,
            receiver_id=target_receiver_id,
            algorithm='AES',
            encrypted_message=encrypted_message
        )

        # Ambil kembali data receiver_user untuk respon JSON
        response_receiver_user = User.get(target_receiver_id)
        response_receiver_username = response_receiver_user.username if response_receiver_user else "Unknown User"
        
        # Untuk tampilan instan di frontend, kirim pesan asli sebagai "original"
        return jsonify({
            'sender': current_user.username,
            'receiver': response_receiver_username,
            'algorithm': 'AES',
            'original': message, # Mengirim pesan asli
            'encrypted': encrypted_message,
            'timestamp': datetime.now().isoformat()
        })

    # Ambil pesan yang relevan untuk user saat ini DAN receiver yang dipilih
    chat_history_raw = []
    if receiver_id:
        chat_history_raw = MessageManager.get_private_messages(current_user.id, receiver_id)

    chat_history_data = []
    for c in chat_history_raw:
        try:
            sender_user = User.get(c['sender_id'])
            receiver_user_msg = User.get(c['receiver_id']) 
            sender_username = sender_user.username if sender_user else "Unknown User"
            receiver_username_msg = receiver_user_msg.username if receiver_user_msg else "Unknown User"

            # Dekripsi ulang dengan kunci global untuk tampilan jika perlu (saat mengambil histori)
            current_decrypted_for_display = decrypt_message_aes(c['encrypted'], AES_GLOBAL_KEY)

            chat_history_data.append({
                'sender': sender_username,
                'receiver': receiver_username_msg,
                'algorithm': 'AES',
                'original': c.get('original'), 
                'encrypted': c['encrypted'],
                'decrypted': current_decrypted_for_display, # Ini adalah pesan yang didekripsi untuk tampilan
                'timestamp': c['timestamp']
            })
        except Exception as e:
            app.logger.error(f'Error processing chat message: {e}')
            continue  # skip this message

    return render_template('chat.html',
                           available_users=User.get_all_except(current_user.id),
                           selected_receiver_id=receiver_id,
                           selected_receiver_username=receiver_username,
                           chat_history=chat_history_data,
                           current_user=current_user,
                           selected_algorithm='AES')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('algorithm', None)
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.create(username, password):
            return redirect(url_for('login'))
        else:
            error = 'Nama pengguna sudah terdaftar.'
            return render_template('register.html', error=error)
    return render_template('register.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    # Placeholder for forgot password functionality
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    # Placeholder for reset password functionality
    return render_template('reset_password.html')

@app.route('/rooms', methods=['GET', 'POST'])
@login_required
def rooms():
    if request.method == 'POST':
        room_name = request.form.get('room_name')
        if room_name:
            # Cek jika room sudah ada atau buat baru
            room = RoomManager.get_by_name(room_name)
            if not room:
                room = RoomManager.create(room_name)
            
            # Tambahkan user ke room member
            RoomMemberManager.add_member(current_user.id, room['id'])
            return redirect(url_for('room_chat', room_id=room['id']))
    
    all_rooms = RoomManager.get_all()
    # Ambil daftar room yang diikuti user
    my_room_ids = RoomMemberManager.get_user_rooms(current_user.id)
    return render_template('rooms.html', rooms=all_rooms, my_room_ids=my_room_ids)

@app.route('/room/<int:room_id>', methods=['GET', 'POST'])
@login_required
def room_chat(room_id):
    room = RoomManager.get_by_id(room_id)
    if not room:
        return redirect(url_for('rooms'))
    
    # Cek apakah user anggota room, jika belum tambahkan
    if not RoomMemberManager.is_member(current_user.id, room_id):
        RoomMemberManager.add_member(current_user.id, room_id)
    
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        message = data.get('message')
        # Algoritma default (misal AES)
        algorithm = 'AES'
        if not message or message.strip() == '':
            return jsonify({'error': 'Pesan tidak boleh kosong.'}), 400
        
        # Kunci global
        AES_GLOBAL_KEY = os.getenv('AES_KEY', 'SixteenByteKey16').encode()
        encrypted_message = encrypt_message_aes(message, AES_GLOBAL_KEY)
        
        MessageManager.create_room_message(
            sender_id=current_user.id,
            room_id=room_id,
            algorithm=algorithm,
            encrypted_message=encrypted_message
        )
        
        # Kirim hasil dekripsi ke frontend, sertakan avatar_color_idx
        return jsonify({
            'sender': current_user.username,
            'decrypted': message,
            'avatar_color_idx': get_avatar_color_idx(current_user.username),
            'timestamp': datetime.now().isoformat()
        })
    
    # Ambil semua pesan di room, lakukan dekripsi
    AES_GLOBAL_KEY = os.getenv('AES_KEY', 'SixteenByteKey16').encode()
    chat_history_raw = MessageManager.get_room_messages(room_id)
    chat_history_data = []
    
    for c in chat_history_raw:
        sender_user = User.get(c['sender_id'])
        sender_username = sender_user.username if sender_user else "Unknown User"
        
        # Dekripsi pesan
        if c['algorithm'] == 'AES':
            decrypted = decrypt_message_aes(c['encrypted'], AES_GLOBAL_KEY)
        else:
            decrypted = "[Unsupported Algorithm]"
        
        chat_history_data.append({
            'sender': sender_username,
            'decrypted': decrypted,
            'avatar_color_idx': get_avatar_color_idx(sender_username),
            'timestamp': c['timestamp']
        })
    
    return render_template('room_chat.html', room=room, chat_history=chat_history_data, current_user=current_user)

@app.route('/room/<int:room_id>/messages', methods=['GET'])
@login_required
def room_messages(room_id):
    room = RoomManager.get_by_id(room_id)
    if not room:
        return jsonify({'error': 'Room not found'}), 404
    
    AES_GLOBAL_KEY = os.getenv('AES_KEY', 'SixteenByteKey16').encode()
    chat_history_raw = MessageManager.get_room_messages(room_id)
    chat_history_data = []
    
    for c in chat_history_raw:
        sender_user = User.get(c['sender_id'])
        sender_username = sender_user.username if sender_user else "Unknown User"
        chat_history_data.append({
            'sender': sender_username,
            'decrypted': decrypt_message_aes(c['encrypted'], AES_GLOBAL_KEY) if c['algorithm'] == 'AES' else "[Unsupported Algorithm]",
            'avatar_color_idx': get_avatar_color_idx(sender_username),
            'timestamp': c['timestamp']
        })
    
    return jsonify(chat_history_data)

@app.route('/delete_room/<int:room_id>', methods=['POST'])
@login_required
def delete_room(room_id):
    # Hanya user yang tergabung di room yang bisa hapus
    if not RoomMemberManager.is_member(current_user.id, room_id):
        return redirect(url_for('rooms'))
    
    RoomManager.delete(room_id)
    return redirect(url_for('rooms'))

if __name__ == '__main__':
    app.run(debug=True)