from flask import Flask, redirect, url_for, session, abort
from datetime import timedelta
from authlib.integrations.flask_client import OAuth
from functools import wraps
from huggingface_hub import InferenceClient
import random
import time


# App config
app = Flask(__name__)
# Session config
app.secret_key = "secrect"
app.config['SESSION_COOKIE_NAME'] = 'huggingface-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=9999)


# oauth config
oauth = OAuth(app)
oauth.register(
    name='huggingface',
    client_id='4b0904ee-f186-4259-9878-3d082fd57e20',
    client_secret='3b29d70f-7566-468d-beb0-d7065159d16a',
    access_token_url='https://huggingface.co/oauth/token',
    access_token_params=None,
    authorize_url=f'https://huggingface.co/oauth/authorize',
    client_kwargs={'scope': 'inference-api'},
    server_metadata_url='https://huggingface.co/.well-known/openid-configuration'
)


# check for session
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = dict(session).get('user_token', None)
        # You would add a check here and usethe user id or something to fetchs
        # the other data for that user/check if they exist
        if user:
            if int(time.time()) > session["user_token"]["expires_at"] - 5:
                return redirect(url_for("login"))
            else:
                return f(*args, **kwargs)
        return redirect(url_for("login"))
    return decorated_function


@app.route('/')
@login_required
def hello_world():
    numbers = []
    client = InferenceClient(
        model = "NousResearch/Hermes-3-Llama-3.1-8B",
        token = dict(session)['user_token']['access_token'],
        timeout = 60.0,
    )
    agent_reply = client.chat_completion(
        messages=[{"role": "user", "content": f"give me a random number between {random.randint(0, 50)} and {random.randint(50, 100)}, dont say anything else"}],
        max_tokens=200,
        stream=False,
    )
    return f'Hello, here is your number: {agent_reply.choices[0].message.content}!'


@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    return oauth.huggingface.authorize_redirect(redirect_uri)


@app.route('/authorize')
def authorize():
    token = oauth.huggingface.authorize_access_token()  # Access token from hugginface (needed to get user info)
    user = oauth.huggingface.userinfo()  # uses openid endpoint to fetch user info
    session['user_token'] = token
    session.permanent = True  # make the session permanant so it keeps existing after broweser gets closed
    return redirect('/')


@app.route('/logout')
def logout():
    for key in list(session.keys()):
        session.pop(key)
    session.clear()
    return redirect('/')


if __name__ == '__main__':
    app.run()