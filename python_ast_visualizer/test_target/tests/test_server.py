import pytest
import io
import json
from app.server import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_parse(client):
    data = 'a: 1\nb: 2'
    rv = client.post('/parse', data=data)
    assert rv.status_code == 200
    assert rv.json['parsed'] == {'a': 1, 'b': 2}

def test_upload(client):
    data = {'file': (io.BytesIO(b'test'), 'test.txt')}
    rv = client.post('/upload', data=data, content_type='multipart/form-data')
    assert rv.status_code == 200
    assert 'file' in rv.json

def test_fetch(client):
    rv = client.get('/fetch?url=http://example.com')
    assert rv.status_code == 200
    assert 'status' in rv.json

def test_encrypt_sign_verify(client):
    rv = client.post('/encrypt', data=b'data')
    assert rv.status_code == 200
    rv1 = client.get('/sign?msg=msg')
    token = rv1.json['token']
    rv2 = client.get(f'/verify?token={token}')
    assert rv2.status_code == 200
    assert rv2.json['ok']
    assert rv2.json['msg'] == 'msg'
