import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import bcrypt
import jwt
import psycopg2
from psycopg2.extras import RealDictCursor
# from google.cloud import trace as cloud_trace
# from google.cloud import profiler
from pythonjsonlogger import jsonlogger

# Google Cloud Traceの初期化
# cloud_trace.Client(project='kh-paloma-m01-01').start()

# Google Cloud Profilerの初期化
"""
try:
    profiler.start(
        service='sample-app-back',
        service_version='1.0.0',
        project_id='kh-paloma-m01-01',
    )
except (OSError, ValueError) as exc:
    logging.error(exc)
"""

app = Flask(__name__)
CORS(app)

# 環境変数からデータベース接続情報を取得
DB_NAME = os.getenv('POSTGRES_DB')
DB_USER = os.getenv('POSTGRES_USER')
DB_PASSWORD = os.getenv('POSTGRES_PASSWORD')
DB_HOST = os.getenv('POSTGRES_SERVER')
DB_PORT = os.getenv('POSTGRES_PORT', 5432)
# psycopg2の接続用URLを構築する
DB_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
# JWTの秘密鍵
JWT_SECRET_KEY = 'your-secret-key'  # 実際の環境では安全に管理してください
db_conn = None

# ロガーの設定
logger = logging.getLogger("backend_logger")
logger.setLevel(logging.INFO)

# コンソールハンドラー
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# ファイルハンドラー
file_handler = RotatingFileHandler('./log/backend.log', maxBytes=10 * 1024 * 1024, backupCount=5)
file_handler.setLevel(logging.INFO)

# JSONフォーマッターの設定
json_formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s')
console_handler.setFormatter(json_formatter)
file_handler.setFormatter(json_formatter)

# ハンドラーをロガーに追加
logger.addHandler(console_handler)
logger.addHandler(file_handler)

# PostgreSQLの接続プールを設定
try:
    db_conn = psycopg2.connect(DB_URL)
    logger.info(f'db_conn: {db_conn}')
    if db_conn:
        print("PostgreSQL connection pool created successfully")
except (Exception, psycopg2.DatabaseError) as error:
    print(f"Error while connecting to PostgreSQL: {error}")


@app.route('/test', methods=['POST'])
def test():
    data = request.get_json()
    if data.get('id') == 'test' and data.get('pass') == 'test':
        return make_response(jsonify({"message": "OK"}), 200)
    else:
        return make_response(jsonify({"message": "Invalid credentials"}), 401)


@app.route('/api/authenticate', methods=['POST'])
def authenticate():
    if db_conn is None:
        return make_response(jsonify({"token": None, "message": "db_conn is None"}), 500)

    data = request.get_json()
    # JSONが空または不正な場合、400エラーを返す
    if data is None or data == {}:
        return make_response(jsonify({"message": "Invalid credentials"}), 401)

    username = data.get('username')
    password = data.get('password')

    logger.info('start authenticate')

    try:
        if db_conn:
            with db_conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
                logger.info(f'cursor {cursor}')
                user = cursor.fetchone()
                logger.info(f'fetched user {user}')

            if not user:
                logger.info('the user does not exist in DB.')
                return make_response(jsonify({"message": "Invalid credentials"}), 401)

            stored_password = user["password"]
            if not bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                logger.info('password is incorrect.')
                return make_response(jsonify({"message": "Invalid credentials"}), 401)

            # JWTペイロードの作成
            jwt_payload = {
                "userId": user["user_id"],
                "username": user["username"],
            }

            # JWTの生成
            token = jwt.encode(jwt_payload, JWT_SECRET_KEY, algorithm='HS256')

            logger.info('login succeed. return jwt token')
            return make_response(jsonify({
                "token": token,
                "message": "Login successful"
            }), 200)

    except Exception as error:
        error_message = f"Error during authentication: [{error.__class__.__name__}] {error}"
        logger.error(error_message)
        return make_response(jsonify({"token": None, "message": error_message}), 500)


if __name__ == '__main__':
    PORT = int(os.getenv('PORT', 3000))
    logger.info(f"Server is running on port {PORT}")
    app.run(host='0.0.0.0', port=PORT)
