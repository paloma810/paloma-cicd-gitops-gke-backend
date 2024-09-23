# import os
# import json
import pytest
from unittest.mock import MagicMock, patch
from app import app as flask_app
import bcrypt


@pytest.fixture
def client():
    flask_app.config['TESTING'] = True
    with flask_app.test_client() as client:
        yield client


# 環境変数を設定するフィクスチャ
@pytest.fixture(autouse=True)
def set_env_vars(monkeypatch):
    monkeypatch.setenv('POSTGRES_DB', 'test_db')
    monkeypatch.setenv('POSTGRES_USER', 'test_user')
    monkeypatch.setenv('POSTGRES_PASSWORD', 'test_password')
    monkeypatch.setenv('POSTGRES_SERVER', 'localhost')
    monkeypatch.setenv('POSTGRES_PORT', '5432')
    # 他の必要な環境変数もここで設定


# モック用のユーザーデータを生成する関数
def get_mock_user():
    hashed_password = bcrypt.hashpw("testpass".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    return {
        "user_id": 1,
        "username": "testuser",
        "password": hashed_password
    }


def test_test_endpoint_success(client):
    response = client.post('/test', json={'id': 'test', 'pass': 'test'})
    assert response.status_code == 200
    assert response.get_json() == {"message": "OK"}


def test_test_endpoint_failure(client):
    response = client.post('/test', json={'id': 'wrong', 'pass': 'wrong'})
    assert response.status_code == 401
    assert response.get_json() == {"message": "Invalid credentials"}


@patch('app.db_conn')
def test_authenticate_db_conn_none(mock_db_conn, client):
    # データベース接続がNoneの場合
    mock_db_conn.return_value = None
    response = client.post('/api/authenticate', json={'username': 'test', 'password': 'test'})
    assert response.status_code == 500


def test_authenticate_invalid_json(client):
    # 無効なJSONデータを送信
    response = client.post('/api/authenticate', data='notjson', content_type='application/json')
    assert response.status_code == 500


@patch('app.db_conn')
def test_authenticate_user_not_found(mock_db_conn, client):
    # ユーザーがデータベースに存在しない場合
    mock_db_conn.return_value = MagicMock()
    mock_cur = mock_db_conn.cursor.return_value.__enter__.return_value
    mock_cur.fetchone.return_value = None

    response = client.post('/api/authenticate', json={'username': 'nonexistent', 'password': 'pass'})
    assert response.status_code == 401
    assert response.get_json() == {"message": "Invalid credentials"}


@patch('app.db_conn')
def test_authenticate_incorrect_password(mock_db_conn, client):
    # 正しいユーザー名だが間違ったパスワードの場合
    mock_user = get_mock_user()
    mock_db_conn.return_value = MagicMock()
    mock_cur = mock_db_conn.cursor.return_value.__enter__.return_value
    mock_cur.fetchone.return_value = mock_user

    response = client.post('/api/authenticate', json={'username': 'testuser', 'password': 'wrongpass'})
    assert response.status_code == 401
    assert response.get_json() == {"message": "Invalid credentials"}


@patch('app.jwt.encode')
@patch('app.db_conn')
def test_authenticate_success(mock_db_conn, mock_jwt_encode, client):
    # 正しいユーザー名とパスワードの場合
    mock_jwt_encode.return_value = 'mocked_jwt_token'
    # 正しいユーザー名だが間違ったパスワードの場合
    mock_user = get_mock_user()
    mock_db_conn.return_value = MagicMock()
    mock_cur = mock_db_conn.cursor.return_value.__enter__.return_value
    mock_cur.fetchone.return_value = mock_user

    response = client.post('/api/authenticate', json={'username': 'testuser', 'password': 'testpass'})
    assert response.status_code == 200
    assert response.get_json() == {
        "token": 'mocked_jwt_token',
        "message": "Login successful"
    }


@patch('app.db_conn')
def test_authenticate_exception(mock_db_conn, client):
    # データベース操作中に例外が発生した場合
    mock_conn = MagicMock()
    mock_conn.cursor.side_effect = Exception("Database error")
    mock_db_conn.return_value = mock_conn

    response = client.post('/api/authenticate', json={'username': 'testuser', 'password': 'testpass'})
    assert response.status_code == 500
