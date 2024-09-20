import os
import pytest
import bcrypt
import jwt
# import json
from unittest.mock import patch, MagicMock
# from flask import Flask
from app import app  # Flaskアプリケーションが app.py にあると仮定


# フィクスチャでテストクライアントを提供
@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


# フィクスチャで環境変数を設定
@pytest.fixture(autouse=True)
def set_env_vars(monkeypatch):
    monkeypatch.setenv('POSTGRES_DB', 'test_db')
    monkeypatch.setenv('POSTGRES_USER', 'test_user')
    monkeypatch.setenv('POSTGRES_PASSWORD', 'test_password')
    monkeypatch.setenv('POSTGRES_SERVER', 'localhost')
    monkeypatch.setenv('POSTGRES_PORT', '5432')
    monkeypatch.setenv('JWT_SECRET_KEY', 'test-secret-key')
    monkeypatch.setenv('PORT', '3001')  # テスト用ポート


# テスト用ユーザーデータ
test_user = {
    'user_id': 1,
    'username': 'testuser',
    'password': bcrypt.hashpw('testpassword'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
}


# `/test` エンドポイントのテスト - 正しい認証
def test_test_endpoint_success(client):
    response = client.post('/test', json={'id': 'test', 'pass': 'test'})
    assert response.status_code == 200
    data = response.get_json()
    assert data['message'] == 'OK'


# `/test` エンドポイントのテスト - 認証エラー
def test_test_endpoint_failure(client):
    response = client.post('/test', json={'id': 'wrong', 'pass': 'wrong'})
    assert response.status_code == 401
    data = response.get_json()
    assert data['message'] == '認証エラー'


# `/api/authenticate` エンドポイントのテスト - 成功
@patch('app.db_pool')
def test_authenticate_success(mock_db_pool, client):
    # モックされたデータベース接続とカーソル
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_db_pool.getconn.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
    # データベースから返されるユーザー情報
    mock_cursor.fetchone.return_value = (
        test_user['user_id'],
        test_user['username'],
        test_user['password']
    )

    response = client.post('/api/authenticate', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert 'token' in data
    assert data['message'] == 'Login successful'

    # データベース接続が正しく行われたか確認
    mock_db_pool.getconn.assert_called_once()
    mock_cursor.execute.assert_called_once_with('SELECT * FROM users WHERE username = %s', ('testuser',))
    mock_db_pool.putconn.assert_called_once_with(mock_conn)


# `/api/authenticate` エンドポイントのテスト - ユーザーが存在しない
@patch('app.db_pool')
def test_authenticate_user_not_found(mock_db_pool, client):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_db_pool.getconn.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
    mock_cursor.fetchone.return_value = None  # ユーザーが見つからない

    response = client.post('/api/authenticate', json={
        'username': 'nonexistent',
        'password': 'any_password'
    })
    assert response.status_code == 401
    data = response.get_json()
    assert data['message'] == 'Invalid credentials'

    mock_db_pool.getconn.assert_called_once()
    mock_cursor.execute.assert_called_once_with('SELECT * FROM users WHERE username = %s', ('nonexistent',))
    mock_db_pool.putconn.assert_called_once_with(mock_conn)


# `/api/authenticate` エンドポイントのテスト - パスワードが間違っている
@patch('app.db_pool')
def test_authenticate_wrong_password(mock_db_pool, client):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_db_pool.getconn.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
    # ユーザーは存在するがパスワードが異なる
    mock_cursor.fetchone.return_value = (
        test_user['user_id'],
        test_user['username'],
        bcrypt.hashpw('wrongpassword'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    )

    response = client.post('/api/authenticate', json={
        'username': 'testuser',
        'password': 'wrongpassword'
    })
    assert response.status_code == 401
    data = response.get_json()
    assert data['message'] == 'Invalid credentials'

    mock_db_pool.getconn.assert_called_once()
    mock_cursor.execute.assert_called_once_with('SELECT * FROM users WHERE username = %s', ('testuser',))
    mock_db_pool.putconn.assert_called_once_with(mock_conn)


# `/api/authenticate` エンドポイントのテスト - データベースエラー
@patch('app.db_pool')
def test_authenticate_db_error(mock_db_pool, client):
    mock_db_pool.getconn.side_effect = Exception("Database connection error")

    response = client.post('/api/authenticate', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 500
    data = response.get_json()
    assert data['token'] is None
    assert data['message'] == 'Internal Server Error'

    mock_db_pool.getconn.assert_called_once()


# JWTトークンの有効性テスト
@patch('app.db_pool')
def test_authenticate_jwt_token(mock_db_pool, client):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_db_pool.getconn.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
    mock_cursor.fetchone.return_value = (
        test_user['user_id'],
        test_user['username'],
        test_user['password']
    )

    response = client.post('/api/authenticate', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 200
    data = response.get_json()
    token = data.get('token')
    assert token is not None

    # JWTトークンのデコードと検証
    decoded = jwt.decode(token, os.getenv('JWT_SECRET_KEY'), algorithms=['HS256'])
    assert decoded['userId'] == test_user['user_id']
    assert decoded['username'] == test_user['username']

    mock_db_pool.getconn.assert_called_once()
    mock_cursor.execute.assert_called_once_with('SELECT * FROM users WHERE username = %s', ('testuser',))
    mock_db_pool.putconn.assert_called_once_with(mock_conn)
