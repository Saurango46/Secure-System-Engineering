from flask import Flask, request, render_template
import bcrypt
import sqlite3
from time import time

app = Flask(__name__)

# Rate limiting + lockout
login_attempts = {}
lockout = {}

MAX_ATTEMPTS = 5
WINDOW = 60        # seconds
LOCK_TIME = 120    # seconds

# DB setup
conn = sqlite3.connect('users.db', check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
''')
conn.commit()

@app.route('/')
def home():
    return render_template('index.html')

# Register
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password'].encode('utf-8')

    # store hash as string
    hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')

    try:
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed)
        )
        conn.commit()

        print("Stored hash in DB:", hashed)
        return "User registered"
    except:
        return "User already exists"

# Login
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password'].encode('utf-8')

    now = time()

    # Lockout check
    if username in lockout:
        if now < lockout[username]:
            return "Account locked. Try later."
        else:
            del lockout[username]

    # Initialize attempt list
    if username not in login_attempts:
        login_attempts[username] = []

    # Remove old attempts
    login_attempts[username] = [
        t for t in login_attempts[username] if now - t < WINDOW
    ]

    # Rate limit check
    if len(login_attempts[username]) >= MAX_ATTEMPTS:
        lockout[username] = now + LOCK_TIME
        return "Too many attempts. Account locked."

    # DB check
    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    result = cursor.fetchone()

    if not result:
        login_attempts[username].append(now)
        return "User not found"

    stored_hash = result[0]

    # FIX: handle both str and bytes safely
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode('utf-8')

    # Password verification
    if bcrypt.checkpw(password, stored_hash):
        login_attempts[username] = []  # reset on success
        return "Login successful"
    else:
        login_attempts[username].append(now)
        return "Invalid credentials"

app.run(debug=True, port=5001)
