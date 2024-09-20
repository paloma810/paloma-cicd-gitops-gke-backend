import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
import jwt
import psycopg2
from google.cloud import trace as cloud_trace
from google.cloud import profiler
from pythonjsonlogger import jsonlogger

# Google Cloud Traceの初期化
cloud_trace.Client(project='kh-paloma-m01-01').start()

# Google Cloud Profilerの初期化
try:
    profiler.start(
        service='sample-app-back',
        service_version='1.0.0',
        project_id='kh-paloma-m01-01',
    )
except (OSError, ValueError) as exc:
    logging.error(exc)

app = Flask(__name__)
CORS(app)

# 環境変数からデータベース接続情報を取得
DB_NAME = os.getenv('POSTGRES_DB')
DB_USER = os.getenv('POSTGRES_USER')
DB_PASSWORD = os.getenv('POSTGRES_PASSWORD')
DB_HOST = os.getenv('POSTGRES_SERVER')
DB_PORT = os.getenv('POSTGRES_PORT', 5432)  # デフォルトのPostgreSQLポート

# JWTの秘密鍵
JWT_SECRET_KEY = 'your-secret-key'  # 実際の環境では安全に管理してください

# PostgreSQLの接続プールを設定
try:
    db_pool = psycopg2.pool.SimpleConnectionPool(
        1,
        20,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME
    )
    if db_pool:
        print("PostgreSQL connection pool created successfully")
except (Exception, psycopg2.DatabaseError) as error:
    print(f"Error while connecting to PostgreSQL: {error}")

# ロガーの設定
logger = logging.getLogger("backend_logger")
logger.setLevel(logging.INFO)

# コンソールハンドラー
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# ファイルハンドラー
file_handler = RotatingFileHandler('/app/log/backend.log', maxBytes = 10 * 1024 * 1024, backupCount = 5)
file_handler.setLevel(logging.INFO)

# JSONフォーマッターの設定
json_formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s')
console_handler.setFormatter(json_formatter)
file_handler.setFormatter(json_formatter)

# ハンドラーをロガーに追加
logger.addHandler(console_handler)
logger.addHandler(file_handler)


@app.route('/test', methods=['POST'])
def test():
    data = request.get_json()
    if data.get('id') == 'test' and data.get('pass') == 'test':
        return jsonify({"message": "OK"})
    else:
        return jsonify({"message": "認証エラー"}), 401


@app.route('/api/authenticate', methods=['POST'])
def authenticate():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    logger.info('start authenticate')

    try:
        conn = db_pool.getconn()
        if conn:
            with conn.cursor() as cursor:
                cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
                user = cursor.fetchone()

            if not user:
                logger.info('the user does not exist in DB.')
                return jsonify({"message": "Invalid credentials"}), 401

            stored_password = user["password"]
            if not bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                logger.info('password is incorrect.')
                return jsonify({"message": "Invalid credentials"}), 401

            # JWTペイロードの作成
            jwt_payload = {
                "userId": user["user_id"],
                "username": user["username"],
            }

            # JWTの生成
            token = jwt.encode(jwt_payload, JWT_SECRET_KEY, algorithm='HS256')

            logger.info('login succeed. return jwt token')
            return jsonify({
                "token": token,
                "message": "Login successful"
            })

    except Exception as error:
        logger.error(f"Error during authentication: {error}")
        return jsonify({"token": None, "message": "Internal Server Error"}), 500
    finally:
        if conn:
            db_pool.putconn(conn)


if __name__ == '__main__':
    PORT = int(os.getenv('PORT', 3000))
    logger.info(f"Server is running on port {PORT}")
    app.run(host='0.0.0.0', port=PORT)
