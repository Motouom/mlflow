from flask import Flask, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
import os
from dotenv import load_dotenv
import secrets

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Load MLflow URL from .env
MLFLOW_URL = os.getenv("MLFLOW_URL")
print(f"MLFLOW_URL loaded: {MLFLOW_URL}")  # Debug to confirm the URL is loaded

oauth = OAuth(app)
keycloak = oauth.register(
    name='keycloak',
    client_id=os.getenv("KEYCLOAK_CLIENT_ID"),
    client_secret=os.getenv("KEYCLOAK_CLIENT_SECRET"),
    server_metadata_url=os.getenv("KEYCLOAK_SERVER_METADATA_URL"),
    client_kwargs={'scope': 'openid email profile'},
)

@app.route('/login')
def login():
    nonce = secrets.token_urlsafe(16)
    session['nonce'] = nonce
    redirect_uri = url_for('auth', _external=True)
    print(f"Redirecting to Keycloak with nonce: {nonce}, redirect_uri: {redirect_uri}")
    return keycloak.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/auth')
def auth():
    try:
        token = oauth.keycloak.authorize_access_token()
        print(f"Token received: {token}")
        nonce = session.get('nonce')
        if not nonce:
            print("Nonce not found in session")
            return "Nonce not found in session", 400
        user_info = oauth.keycloak.parse_id_token(token, nonce)
        print(f"User info: {user_info}")
        session['user'] = user_info
        print(f"Redirecting to MLflow URL: {MLFLOW_URL}")
        return redirect(MLFLOW_URL)
    except Exception as e:
        print(f"Error in /auth: {str(e)}")
        return f"Authentication error: {str(e)}", 500

@app.route('/logout')
def logout():
    # Clear the Flask session
    session.clear()
    print("Session cleared")

    # Redirect to Keycloak's logout endpoint
    keycloak_logout_url = (
        f"{os.getenv('KEYCLOAK_SERVER_METADATA_URL').replace('/.well-known/openid-configuration', '')}/protocol/openid-connect/logout"
        f"?redirect_uri={url_for('login', _external=True)}"
    )
    print(f"Redirecting to Keycloak logout: {keycloak_logout_url}")
    return redirect(keycloak_logout_url)

@app.route('/')
def index():
    if 'user' not in session:
        print("User not logged in, redirecting to login")
        return redirect(url_for('login'))
    user = session['user']
    print(f"Index accessed, session user: {user}")
    return "Logged in as: " + str(user)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)  # Enable debug mode