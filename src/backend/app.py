import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import bcrypt
import jwt
import psycopg2
import datetime
from psycopg2.extras import RealDictCursor
from pythonjsonlogger import jsonlogger

class Database:
    def __init__(self):
        self.DB_NAME = os.getenv('POSTGRES_DB')
        self.DB_USER = os.getenv('POSTGRES_USER')
        self.DB_PASSWORD = os.getenv('POSTGRES_PASSWORD')
        self.DB_HOST = os.getenv('POSTGRES_SERVER')
        self.DB_PORT = os.getenv('POSTGRES_PORT', 5432)
        self.DB_URL = f"postgresql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    def get_connection(self):
        try:
            connection = psycopg2.connect(self.DB_URL)
            return connection
        except (Exception, psycopg2.DatabaseError) as error:
            print(f"Error while connecting to PostgreSQL: {error}")
            return None

class LoggerService:
    def __init__(self):
        self.logger = logging.getLogger("backend_logger")
        self.logger.setLevel(logging.INFO)
        self._setup_handlers()

    def _setup_handlers(self):
        console_handler = logging.StreamHandler()
        file_handler = RotatingFileHandler('./log/backend.log', maxBytes=10 * 1024 * 1024, backupCount=5)

        json_formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s')
        console_handler.setFormatter(json_formatter)
        file_handler.setFormatter(json_formatter)

        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

    def info(self, message):
        self.logger.info(message)

    def error(self, message):
        self.logger.error(message)

class AuthService:
    JWT_SECRET_KEY = 'your-secret-key'

    def __init__(self, db, logger):
        self.db = db
        self.logger = logger

    def authenticate(self, username, password):
        connection = self.db.get_connection()
        if connection is None:
            return None, "Database connection failed"

        try:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
                user = cursor.fetchone()

            if not user:
                return None, "Invalid credentials"

            stored_password = user["password"]
            if not bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                return None, "Invalid credentials"

            jwt_payload = {
                "userId": user["user_id"],
                "username": user["username"],
                'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10),
            }

            token = jwt.encode(jwt_payload, AuthService.JWT_SECRET_KEY, algorithm='HS256')
            return token, "Login successful"

        except Exception as error:
            error_message = f"Error during authentication: [{error.__class__.__name__}] {error}"
            self.logger.error(error_message)
            return None, error_message
        finally:
            connection.close()

app = Flask(__name__)
CORS(app)

db = Database()
logger_service = LoggerService()
auth_service = AuthService(db, logger_service)

@app.route('/test', methods=['POST'])
def test():
    data = request.get_json()
    if data.get('id') == 'test' and data.get('pass') == 'test':
        return make_response(jsonify({"message": "OK"}), 200)
    else:
        return make_response(jsonify({"message": "Invalid credentials"}), 401)

@app.route('/api/authenticate', methods=['POST'])
def authenticate():
    data = request.get_json()
    if data is None or data == {}:
        return make_response(jsonify({"message": "Invalid credentials"}), 401)

    username = data.get('username')
    password = data.get('password')

    token, message = auth_service.authenticate(username, password)
    if token:
        return make_response(jsonify({
            "token": token,
            "message": message
        }), 200)
    else:
        return make_response(jsonify({
            "token": None,
            "message": message
        }), 401)

if __name__ == '__main__':
    PORT = int(os.getenv('PORT', 3000))
    logger_service.info(f"Server is running on port {PORT}")
    app.run(host='0.0.0.0', port=PORT)
