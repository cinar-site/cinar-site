from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
from dotenv import load_dotenv
import sqlite3
import random
import smtplib
from email.mime.text import MIMEText
from werkzeug.security import generate_password_hash, check_password_hash
import string
import secrets

load_dotenv()

app = Flask(__name__)
app.secret_key = "super_secret_key_123"

SENDER_EMAIL = os.getenv("EMAIL_USER")
SENDER_PASSWORD = os.getenv("EMAIL_PASS")

# ---------------------------
# DATABASE OLUŞTUR
# ---------------------------
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            reset_token TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------------------------
# MAIL GÖNDER
# ---------------------------
def send_email(receiver_email, subject, body):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = receiver_email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)

# ---------------------------
# REGISTER
# ---------------------------
@app.route("/", methods=["GET", "POST"])
@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        password2 = request.form["password2"]

        if password != password2:
            flash("Şifreler eşleşmiyor!")
            return redirect(url_for("register"))

        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        if c.fetchone():
            conn.close()
            flash("Bu email zaten kayıtlı!")
            return redirect(url_for("register"))
        conn.close()

        code = str(random.randint(100000, 999999))
        session["verify_code"] = code
        session["temp_name"] = name
        session["temp_email"] = email
        session["temp_password"] = generate_password_hash(password)

        try:
            send_email(email, "Site Doğrulama Kodu", f"Kayıt kodunuz: {code}")
            flash("Doğrulama kodu gönderildi!")
        except Exception as e:
            flash(f"Mail gönderilemedi: {e}")
            return redirect(url_for("register"))

        return redirect(url_for("verify"))

    return render_template("register.html")

# ---------------------------
# VERIFY
# ---------------------------
@app.route("/verify", methods=["GET", "POST"])
def verify():
    if "verify_code" not in session:
        flash("Önce kayıt olmanız gerekiyor!")
        return redirect(url_for("register"))

    if request.method == "POST":
        user_code = request.form["code"]

        if user_code == session.get("verify_code"):
            name = session.pop("temp_name")
            email = session.pop("temp_email")
            password = session.pop("temp_password")
            session.pop("verify_code", None)

            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                      (name, email, password))
            conn.commit()
            conn.close()

            flash("Kayıt başarılı! Giriş yapabilirsiniz.")
            return redirect(url_for("login"))
        else:
            flash("Hatalı kod!")
            return redirect(url_for("verify"))

    return render_template("verify.html")

# ---------------------------
# LOGIN
# ---------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session["user_id"] = user[0]
            session["user_name"] = user[1]
            flash(f"Hoşgeldiniz, {user[1]}!")
            return redirect(url_for("dashboard"))
        else:
            flash("Email veya şifre hatalı!")
            return redirect(url_for("login"))

    return render_template("login.html")

# ---------------------------
# DASHBOARD
# ---------------------------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Önce giriş yapmalısınız!")
        return redirect(url_for("login"))

    return render_template("dashboard.html", name=session["user_name"])

# ---------------------------
# LOGOUT
# ---------------------------
@app.route("/logout")
def logout():
    session.clear()
    flash("Çıkış yapıldı!")
    return redirect(url_for("login"))

# ---------------------------
# FORGOT PASSWORD
# ---------------------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]

        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        user = c.fetchone()

        if user:
            token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20))
            c.execute("UPDATE users SET reset_token=? WHERE email=?", (token, email))
            conn.commit()

            try:
                reset_link = url_for('reset_password', token=token, _external=True)
                send_email(email, "Şifre Sıfırlama",
                           f"Şifrenizi sıfırlamak için tıklayın: {reset_link}")
                flash("Şifre sıfırlama linki gönderildi!")
            except Exception as e:
                flash(f"Mail gönderilemedi: {e}")
        else:
            flash("Bu email sistemde kayıtlı değil!")

        conn.close()
        return redirect(url_for("login"))

    return render_template("forgot_password.html")

# ---------------------------
# RESET PASSWORD
# ---------------------------
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE reset_token=?", (token,))
    user = c.fetchone()

    if not user:
        flash("Geçersiz token!")
        conn.close()
        return redirect(url_for("login"))

    if request.method == "POST":
        new_password = request.form["password"]
        new_password2 = request.form["password2"]

        if new_password != new_password2:
            flash("Şifreler eşleşmiyor!")
            return redirect(url_for("reset_password", token=token))

        hashed_password = generate_password_hash(new_password)
        c.execute("UPDATE users SET password=?, reset_token=NULL WHERE id=?",
                  (hashed_password, user[0]))
        conn.commit()
        conn.close()

        flash("Şifre başarıyla güncellendi!")
        return redirect(url_for("login"))

    conn.close()
    return render_template("reset_password.html")

# ---------------------------
# SETTINGS / AYARLAR
# ---------------------------
@app.route("/dashboard/settings")
def settings():
    if "user_id" not in session:
        flash("Önce giriş yapmalısınız!")
        return redirect(url_for("login"))

    # settings.html template'i oluşturulmalı
    return render_template("settings.html", name=session.get("user_name"))

# ---------------------------
# RUN
# ---------------------------
if __name__ == "__main__":
    app.run(debug=True)