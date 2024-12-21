from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('POSTGRES_CONN', 'sqlite:///test.db')
app.config['JWT_SECRET_KEY'] = os.getenv('RANDOM_SECRET', 'super-secret-key')

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    country_code = db.Column(db.String(2), nullable=False)
    is_public = db.Column(db.Boolean, default=True)
    phone = db.Column(db.String(20), nullable=True)
    image = db.Column(db.String(200), nullable=True)

def init_db():
    with app.app_context():
        db.create_all()

def error_response(message, status_code):
    return jsonify({"reason": message}), status_code

@app.route('/api/ping', methods=['GET'])
def ping():
    return jsonify({"status": "ok"}), 200

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    if not data:
        return error_response("Invalid input", 400)

    try:
        login = data['login']
        email = data['email']
        password = data['password']
        country_code = data['countryCode']
        is_public = data['isPublic']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        if User.query.filter((User.login == login) | (User.email == email)).first():
            return error_response("User with provided login or email already exists", 409)

        user = User(login=login, email=email, password=hashed_password, country_code=country_code, is_public=is_public)
        db.session.add(user)
        db.session.commit()

        return jsonify({"profile": {
            "login": login,
            "email": email,
            "countryCode": country_code,
            "isPublic": is_public,
        }}), 201
    except KeyError as e:
        return error_response(f"Missing key: {e.args[0]}", 400)

@app.route('/api/auth/sign-in', methods=['POST'])
def sign_in():
    data = request.json
    if not data:
        return error_response("Invalid input", 400)

    login = data.get('login')
    password = data.get('password')
    user = User.query.filter_by(login=login).first()

    if user and bcrypt.check_password_hash(user.password, password):
        token = create_access_token(identity=user.id)
        return jsonify({"token": token}), 200
    return error_response("Invalid login or password", 401)

@app.route('/api/me/profile', methods=['GET', 'PATCH'])
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return error_response("User not found", 404)

    if request.method == 'GET':
        return jsonify({
            "login": user.login,
            "email": user.email,
            "countryCode": user.country_code,
            "isPublic": user.is_public,
            "phone": user.phone,
            "image": user.image
        }), 200

    if request.method == 'PATCH':
        data = request.json
        if not data:
            return jsonify({
                "login": user.login,
                "email": user.email,
                "countryCode": user.country_code,
                "isPublic": user.is_public,
                "phone": user.phone,
                "image": user.image
            }), 200

        user.country_code = data.get('countryCode', user.country_code)
        user.is_public = data.get('isPublic', user.is_public)
        user.phone = data.get('phone', user.phone)
        user.image = data.get('image', user.image)

        db.session.commit()

        return jsonify({
            "login": user.login,
            "email": user.email,
            "countryCode": user.country_code,
            "isPublic": user.is_public,
            "phone": user.phone,
            "image": user.image
        }), 200

@app.route('/api/profiles/<string:login>', methods=['GET'])
@jwt_required()
def get_profile(login):
    current_user_id = get_jwt_identity()
    user = User.query.filter_by(login=login).first()

    if not user:
        return error_response("User not found", 403)

    if not user.is_public and user.id != current_user_id:
        return error_response("Access denied", 403)

    return jsonify({
        "login": user.login,
        "email": user.email,
        "countryCode": user.country_code,
        "isPublic": user.is_public,
        "phone": user.phone,
        "image": user.image
    }), 200

@app.route('/api/me/updatePassword', methods=['POST'])
@jwt_required()
def update_password():
    data = request.json
    if not data:
        return error_response("Invalid input", 400)

    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return error_response("User not found", 404)

    old_password = data.get('oldPassword')
    new_password = data.get('newPassword')

    if not bcrypt.check_password_hash(user.password, old_password):
        return error_response("Invalid current password", 403)

    user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    db.session.commit()

    return jsonify({"status": "ok"}), 200

if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0", port=int(os.getenv('SERVER_PORT', 8080)))
