import pytest
import bcrypt
import jwt
from unittest.mock import patch, MagicMock
from app import app

# JWTの秘密鍵とテストユーザーの設定
JWT_SECRET_KEY = 'your-secret-key'
TEST_USER = {
    'username': 'testuser',
    'password': bcrypt.hashpw('testpass'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
    'user_id': 1
}


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_test_endpoint(client):
    """ /test エンドポイントのテスト """
    response = client.post('/test', json={'id': 'test', 'pass': 'test'})
    assert response.status_code == 200
    assert response.json['message'] == 'OK'

    response = client.post('/test', json={'id': 'wrong', 'pass': 'test'})
    assert response.status_code == 401
    assert response.json['message'] == 'Invalid credentials'


@patch('app.Database.get_connection')
def test_authenticate_success(mock_get_connection, client):
    """ 認証成功時のテスト """
    mock_conn = MagicMock()
    mock_cursor = mock_conn.cursor.return_value.__enter__.return_value
    mock_cursor.fetchone.return_value = TEST_USER
    mock_get_connection.return_value = mock_conn

    response = client.post('/api/authenticate', json={'username': 'testuser', 'password': 'testpass'})
    assert response.status_code == 200
    assert 'token' in response.json
    assert response.json['message'] == 'Login successful'

    # JWTの検証
    token = response.json['token']
    decoded_token = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
    assert decoded_token['username'] == 'testuser'
    assert decoded_token['userId'] == 1


@patch('app.Database.get_connection')
def test_authenticate_invalid_user(mock_get_connection, client):
    """ 無効なユーザーの場合の認証テスト """
    mock_conn = MagicMock()
    mock_cursor = mock_conn.cursor.return_value.__enter__.return_value
    mock_cursor.fetchone.return_value = None  # ユーザーが存在しない場合
    mock_get_connection.return_value = mock_conn

    response = client.post('/api/authenticate', json={'username': 'unknown', 'password': 'wrongpass'})
    assert response.status_code == 401
    assert response.json['message'] == 'Invalid credentials'


@patch('app.Database.get_connection')
def test_authenticate_invalid_password(mock_get_connection, client):
    """ パスワードが間違っている場合の認証テスト """
    mock_conn = MagicMock()
    mock_cursor = mock_conn.cursor.return_value.__enter__.return_value
    mock_cursor.fetchone.return_value = TEST_USER
    mock_get_connection.return_value = mock_conn

    response = client.post('/api/authenticate', json={'username': 'testuser', 'password': 'wrongpass'})
    assert response.status_code == 401
    assert response.json['message'] == 'Invalid credentials'


@patch('app.Database.get_connection')
def test_authenticate_db_error(mock_get_connection, client):
    """ データベースエラー時の認証テスト """
    mock_get_connection.side_effect = Exception
