# tests/test_app.py

import os
import sys
import pytest
from unittest.mock import patch, MagicMock
# import bcrypt
# import jwt

# 1. psycopg2.pool.SimpleConnectionPool をモックする
with patch('psycopg2.pool.SimpleConnectionPool') as mock_pool:
    mock_db_pool = MagicMock()
    mock_pool.return_value = mock_db_pool

    # 2. 必要な環境変数を設定する
    os.environ['POSTGRES_DB'] = 'test_db'
    os.environ['POSTGRES_USER'] = 'test_user'
    os.environ['POSTGRES_PASSWORD'] = 'test_password'
    os.environ['POSTGRES_SERVER'] = 'localhost'
    os.environ['POSTGRES_PORT'] = '5432'
    # JWT_SECRET_KEY が環境変数として扱われていない場合、app.py を修正することも検討

    # 3. 親ディレクトリをパスに追加して app.py をインポートする
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app import app


# 4. テストクライアントのフィクスチャを定義
@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


# 5. /test エンドポイントのテスト

def test_test_endpoint_success(client):
    response = client.post('/test', json={'id': 'test', 'pass': 'test'})
    assert response.status_code == 200
    assert response.get_json() == {"message": "OK"}


def test_test_endpoint_failure(client):
    response = client.post('/test', json={'id': 'wrong', 'pass': 'test'})
    assert response.status_code == 401
    assert response.get_json() == {"message": "認証エラー"}

    response = client.post('/test', json={'id': 'test', 'pass': 'wrong'})
    assert response.status_code == 401
    assert response.get_json() == {"message": "認証エラー"}


# 6. /api/authenticate エンドポイントのテスト

@patch('app.db_pool')
def test_authenticate_success(mock_db_pool, client):
    # モックされたデータベース接続とカーソルの設定
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_db_pool.getconn.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

    # データベースから返されるユーザーデータ
    mock_cursor.fetchone.return_value = {
        "user_id": 1,
        "username": "testuser",
        # "password": bcrypt.hashpw(b'testpassword', bcrypt.gensalt()).decode('utf-8')
        "password": "testpassword"
    }

    # bcrypt.checkpw をモック
    with patch('app.bcrypt.checkpw', return_value=True):
        # jwt.encode をモック
        with patch('app.jwt.encode', return_value='mocked_jwt_token'):
            response = client.post('/api/authenticate', json={
                'username': 'testuser',
                'password': 'testpassword'
            })
            assert response.status_code == 200
            json_data = response.get_json()
            assert json_data['token'] == 'mocked_jwt_token'
            assert json_data['message'] == "Login successful"

    # コネクションがプールに返されることを確認
    mock_db_pool.putconn.assert_called_with(mock_conn)


@patch('app.db_pool')
def test_authenticate_user_not_found(mock_db_pool, client):
    # モックされたデータベース接続とカーソルの設定
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_db_pool.getconn.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

    # データベースから返されるユーザーデータが None
    mock_cursor.fetchone.return_value = None

    response = client.post('/api/authenticate', json={
        'username': 'nonexistent',
        'password': 'any_password'
    })
    assert response.status_code == 401
    assert response.get_json() == {"message": "Invalid credentials"}

    # コネクションがプールに返されることを確認
    mock_db_pool.putconn.assert_called_with(mock_conn)


@patch('app.db_pool')
def test_authenticate_incorrect_password(mock_db_pool, client):
    # モックされたデータベース接続とカーソルの設定
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_db_pool.getconn.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

    # データベースから返されるユーザーデータ
    mock_cursor.fetchone.return_value = {
        "user_id": 1,
        "username": "testuser",
        # "password": bcrypt.hashpw(b'correct_password', bcrypt.gensalt()).decode('utf-8')
        "password": "testpassword"
    }

    # bcrypt.checkpw をモックして False を返す
    with patch('app.bcrypt.checkpw', return_value=False):
        response = client.post('/api/authenticate', json={
            'username': 'testuser',
            'password': 'wrongpassword'
        })
        assert response.status_code == 401
        assert response.get_json() == {"message": "Invalid credentials"}

    # コネクションがプールに返されることを確認
    mock_db_pool.putconn.assert_called_with(mock_conn)


@patch('app.db_pool')
def test_authenticate_internal_server_error(mock_db_pool, client):
    # db_pool.getconn が例外を投げるように設定
    mock_db_pool.getconn.side_effect = Exception("Database connection error")

    response = client.post('/api/authenticate', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 500
    assert response.get_json() == {"token": None, "message": "Internal Server Error"}


# 7. 追加のテストケース（オプション）

@patch('app.db_pool')
def test_authenticate_missing_fields(mock_db_pool, client):
    # モックされたデータベース接続とカーソルの設定
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_db_pool.getconn.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

    # データベースから返されるユーザーデータが None
    mock_cursor.fetchone.return_value = None

    # ユーザー名が欠けている
    response = client.post('/api/authenticate', json={
        'password': 'testpassword'
    })
    assert response.status_code == 401
    assert response.get_json() == {"message": "Invalid credentials"}

    # コネクションがプールに返されることを確認
    mock_db_pool.putconn.assert_called_with(mock_conn)


def test_authenticate_empty_json(client):
    response = client.post('/api/authenticate', json={})
    assert response.status_code == 401
    assert response.get_json() == {"message": "Invalid credentials"}


def test_authenticate_no_json(client):
    response = client.post('/api/authenticate', data="Not a JSON")
    # 現在の app.py の実装では、`data.get('username')` が None になるため 401 が返されます
    assert response.status_code == 415
    assert response.get_json() is None
