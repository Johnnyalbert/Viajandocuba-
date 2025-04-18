import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import secrets
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Permite peticiones desde tu frontend

# Configuración (usa variables de entorno en Render)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace("postgres://", "postgresql://", 1)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

db = SQLAlchemy(app)
mail = Mail(app)

# Modelo de Usuario
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    reset_token = db.Column(db.String(100), nullable=True)

# Crear tablas (ejecuta esto solo una vez)
with app.app_context():
    db.create_all()

# --- Endpoints ---

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Usuario registrado"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):
        return jsonify({"message": "Inicio de sesión exitoso"}), 200
    return jsonify({"error": "Credenciales inválidas"}), 401

@app.route('/reset-password', methods=['POST'])
def reset_password():
    email = request.json.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "Email no registrado"}), 404
    
    # Generar token y enviar correo
    token = secrets.token_urlsafe(32)
    user.reset_token = token
    db.session.commit()
    
    msg = Message('Recuperación de contraseña', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'Usa este enlace para restablecer tu contraseña: https://tufrontend.com/reset?token={token}'
    mail.send(msg)
    
    return jsonify({"message": "Correo enviado"}), 200

@app.route('/delete-account', methods=['DELETE'])
def delete_account():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "Cuenta eliminada"}), 200
    return jsonify({"error": "Credenciales inválidas"}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)