from flask import Flask, request, render_template
import bcrypt
import sqlite3
import pyotp
import qrcode

app = Flask(__name__)

# DB setup
conn = sqlite3.connect('users.db', check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    totp_secret TEXT
)
''')
conn.commit()

# ---------------- HOME ----------------
@app.route('/')
def home():
    return render_template('index.html')

# ---------------- REGISTER ----------------
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password'].encode('utf-8')

    hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')

    # Generate TOTP secret
    totp_secret = pyotp.random_base32()

    try:
        cursor.execute(
            "INSERT INTO users (username, password, totp_secret) VALUES (?, ?, ?)",
            (username, hashed, totp_secret)
        )
        conn.commit()

        # Generate QR code
        totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(
            name=username, issuer_name="SecureApp"
        )

        img = qrcode.make(totp_uri)
        img.save("static/qrcode.png")

        return "Registered! Now go to /qrcode to scan"
    except:
        return "User already exists"

# ---------------- SHOW QR ----------------
@app.route('/qrcode')
def show_qr():
    return '<img src="/static/qrcode.png">'

# ---------------- LOGIN STEP 1 ----------------
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password'].encode('utf-8')

    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    result = cursor.fetchone()

    if not result:
        return "User not found"

    stored_hash = result[0]
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode('utf-8')

    if bcrypt.checkpw(password, stored_hash):
        return render_template("otp.html", username=username)
    else:
        return "Invalid credentials"

# ---------------- OTP VERIFY ----------------
last_otp = {}

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    username = request.form['username']
    otp = request.form['otp']

    cursor.execute("SELECT totp_secret FROM users WHERE username=?", (username,))
    result = cursor.fetchone()

    if not result:
        return "User not found"

    totp_secret = result[0]
    totp = pyotp.TOTP(totp_secret)

    # Replay protection
    if username in last_otp and last_otp[username] == otp:
        return "OTP replay detected"

    if totp.verify(otp):
        last_otp[username] = otp
        return "2FA Login successful"
    else:
        return "Invalid OTP"

app.run(debug=True, port=5002)
