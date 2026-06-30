import json
import os
import re
import secrets
from dotenv import load_dotenv
from flask import Flask, request, Response, send_from_directory, session, jsonify, redirect, url_for
from groq import Groq
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth

load_dotenv()

app = Flask(__name__, static_folder='public')
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False

API_KEY = os.environ.get('GROQ_API_KEY', '')
client = Groq(api_key=API_KEY) if API_KEY else None

USERS_FILE = os.path.join(os.path.dirname(__file__), 'users.json')

# ── OAuth setup ────────────────────────────────────────────────
oauth = OAuth(app)

if os.environ.get('GOOGLE_CLIENT_ID'):
    oauth.register(
        name='google',
        client_id=os.environ.get('GOOGLE_CLIENT_ID'),
        client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
    )

if os.environ.get('MICROSOFT_CLIENT_ID'):
    oauth.register(
        name='microsoft',
        client_id=os.environ.get('MICROSOFT_CLIENT_ID'),
        client_secret=os.environ.get('MICROSOFT_CLIENT_SECRET'),
        server_metadata_url='https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
    )


def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE) as f:
        return json.load(f)


def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)


# ── Static pages ───────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('public', 'index.html')


@app.route('/weather.html')
@app.route('/weather')
def weather():
    return send_from_directory('public', 'weather.html')


# ── Auth: username/password ────────────────────────────────────
@app.post('/api/register')
def register():
    body = request.get_json()
    username = (body.get('username') or '').strip().lower()
    password = body.get('password') or ''

    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400
    if len(username) < 3 or len(username) > 20:
        return jsonify({'error': 'Username must be 3–20 characters.'}), 400
    if not re.fullmatch(r'[a-z0-9_.]+', username):
        return jsonify({'error': 'Username may only contain letters, numbers, underscores, and periods.'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters.'}), 400
    if not re.search(r'[A-Z]', password):
        return jsonify({'error': 'Password must contain at least one uppercase letter.'}), 400
    if not re.search(r'[a-z]', password):
        return jsonify({'error': 'Password must contain at least one lowercase letter.'}), 400
    if not re.search(r'[0-9]', password):
        return jsonify({'error': 'Password must contain at least one number.'}), 400
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;\'`~/]', password):
        return jsonify({'error': 'Password must contain at least one special character (e.g. !, @, #, $).'}), 400

    users = load_users()
    if username in users:
        return jsonify({'error': 'Username already taken.'}), 409

    users[username] = generate_password_hash(password, method='pbkdf2:sha256')
    save_users(users)
    session['username'] = username
    session['auth_type'] = 'password'
    return jsonify({'username': username})


@app.post('/api/login')
def login():
    body = request.get_json()
    username = (body.get('username') or '').strip().lower()
    password = body.get('password') or ''

    users = load_users()
    if username not in users or not check_password_hash(users[username], password):
        return jsonify({'error': 'Invalid username or password.'}), 401

    session['username'] = username
    session['auth_type'] = 'password'
    return jsonify({'username': username})


@app.post('/api/guest')
def guest():
    session['username'] = 'Guest'
    session['auth_type'] = 'guest'
    return jsonify({'username': 'Guest'})


@app.post('/api/change-username')
def change_username():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in.'}), 401
    auth_type = session.get('auth_type', 'password')
    if auth_type == 'guest':
        return jsonify({'error': 'Guests cannot change their display name.'}), 400

    body = request.get_json()
    new_username = (body.get('newUsername') or '').strip()
    if not new_username:
        return jsonify({'error': 'New username is required.'}), 400

    if auth_type == 'password':
        new_username = new_username.lower()
        if len(new_username) < 3 or len(new_username) > 20:
            return jsonify({'error': 'Username must be 3–20 characters.'}), 400
        if not re.fullmatch(r'[a-z0-9_.]+', new_username):
            return jsonify({'error': 'Only letters, numbers, underscores, and periods allowed.'}), 400
        users = load_users()
        if new_username in users and new_username != session['username']:
            return jsonify({'error': 'Username already taken.'}), 409
        users[new_username] = users.pop(session['username'])
        save_users(users)

    session['username'] = new_username
    return jsonify({'username': new_username})


@app.post('/api/change-password')
def change_password():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in.'}), 401
    auth_type = session.get('auth_type', 'password')
    if auth_type == 'google':
        return jsonify({'error': 'Your password is managed by Google.'}), 400
    if auth_type == 'guest':
        return jsonify({'error': 'Guests cannot change their password.'}), 400
    current = session['username']
    users = load_users()
    if current not in users:
        return jsonify({'error': 'Account not found.'}), 400

    body = request.get_json()
    current_pw = body.get('currentPassword') or ''
    new_pw     = body.get('newPassword') or ''

    if not check_password_hash(users[current], current_pw):
        return jsonify({'error': 'Current password is incorrect.'}), 401
    if len(new_pw) < 8:
        return jsonify({'error': 'New password must be at least 8 characters.'}), 400
    if not re.search(r'[A-Z]', new_pw):
        return jsonify({'error': 'New password must contain an uppercase letter.'}), 400
    if not re.search(r'[a-z]', new_pw):
        return jsonify({'error': 'New password must contain a lowercase letter.'}), 400
    if not re.search(r'[0-9]', new_pw):
        return jsonify({'error': 'New password must contain a number.'}), 400
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;\'`~/]', new_pw):
        return jsonify({'error': 'New password must contain a special character.'}), 400

    users[current] = generate_password_hash(new_pw, method='pbkdf2:sha256')
    save_users(users)
    return jsonify({'ok': True})


@app.post('/api/logout')
def logout():
    session.clear()
    return jsonify({'ok': True})


@app.get('/api/me')
def me():
    if 'username' in session:
        return jsonify({'username': session['username'], 'auth_type': session.get('auth_type', 'password')})
    return jsonify({'username': None})


# ── Auth: Google OAuth ─────────────────────────────────────────
@app.route('/auth/google')
def auth_google():
    if not os.environ.get('GOOGLE_CLIENT_ID'):
        return redirect('/?oauth_error=Google+credentials+not+configured')
    redirect_uri = url_for('auth_google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route('/auth/google/callback')
def auth_google_callback():
    try:
        token = oauth.google.authorize_access_token()
        user = token.get('userinfo') or {}
        name = user.get('name') or user.get('email', 'Google User')
        session['username'] = name
        session['auth_type'] = 'google'
    except Exception as e:
        print(f'Google OAuth error: {e}')
        return redirect(f'/?oauth_error={str(e)[:120]}')
    return redirect('/')


# ── Auth: Microsoft OAuth ──────────────────────────────────────
@app.route('/auth/microsoft')
def auth_microsoft():
    if not os.environ.get('MICROSOFT_CLIENT_ID'):
        return redirect('/?oauth_error=Microsoft+credentials+not+configured')
    redirect_uri = url_for('auth_microsoft_callback', _external=True)
    return oauth.microsoft.authorize_redirect(redirect_uri)


@app.route('/auth/microsoft/callback')
def auth_microsoft_callback():
    try:
        token = oauth.microsoft.authorize_access_token()
        user = token.get('userinfo') or {}
        name = user.get('name') or user.get('email', 'Microsoft User')
        session['username'] = name
    except Exception:
        return redirect('/?oauth_error=Microsoft+sign-in+failed')
    return redirect('/')


# ── Chat ───────────────────────────────────────────────────────
@app.post('/api/chat')
def chat():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in.'}), 401
    if not client:
        return jsonify({'error': 'GROQ_API_KEY not set.'}), 500

    body = request.get_json()
    messages = body.get('messages', [])
    system_prompt = body.get('systemPrompt', 'You are a helpful, friendly AI assistant.')
    context = body.get('context', {})

    system_parts = [system_prompt]
    if context.get('datetime'):
        system_parts.append(f"Current date and time: {context['datetime']}.")
    if context.get('weather'):
        system_parts.append(f"User's current weather: {context['weather']}.")

    full_messages = [{'role': 'system', 'content': '\n\n'.join(system_parts)}] + messages

    def stream():
        try:
            completion = client.chat.completions.create(
                model='llama-3.3-70b-versatile',
                messages=full_messages,
                stream=True,
            )
            for chunk in completion:
                text = chunk.choices[0].delta.content
                if text:
                    yield f'data: {json.dumps({"text": text})}\n\n'
            yield 'data: [DONE]\n\n'
        except Exception as e:
            yield f'data: {json.dumps({"error": str(e)})}\n\n'

    return Response(stream(), mimetype='text/event-stream')


# ── ElevenLabs TTS proxy ───────────────────────────────────────
@app.post('/api/tts')
def tts():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in.'}), 401
    body = request.get_json()
    text     = (body.get('text') or '').strip()[:2500]
    voice_id = body.get('voice_id') or '21m00Tcm4TlvDq8ikWAM'
    api_key  = (body.get('api_key') or '').strip()
    if not text or not api_key:
        return jsonify({'error': 'Missing text or api_key'}), 400

    resp = requests.post(
        f'https://api.elevenlabs.io/v1/text-to-speech/{voice_id}',
        headers={'xi-api-key': api_key, 'Content-Type': 'application/json', 'Accept': 'audio/mpeg'},
        json={'text': text, 'model_id': 'eleven_turbo_v2_5', 'voice_settings': {'stability': 0.45, 'similarity_boost': 0.80}},
        timeout=20,
    )
    if resp.status_code != 200:
        return jsonify({'error': f'ElevenLabs error {resp.status_code}'}), 502
    return Response(resp.content, mimetype='audio/mpeg')


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    if not API_KEY:
        print('\n  WARNING: GROQ_API_KEY not set.')
    else:
        print(f'\n  ROBOTI Chatbot running at http://localhost:{port}\n')
    app.run(port=port, debug=False)
