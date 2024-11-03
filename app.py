from flask import Flask, redirect, url_for,session
from datetime import timedelta
from authlib.integrations.flask_client import OAuth
from functools import wraps
from huggingface_hub import InferenceClient
import random


# check for session
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = dict(session).get('token', None)
        # You would add a check here and usethe user id or something to fetch
        # the other data for that user/check if they exist
        if user:
            return f(*args, **kwargs)
        return redirect(url_for("login"))
    return decorated_function


# App config
app = Flask(__name__)
# Session config
app.secret_key = "secrect"
app.config['SESSION_COOKIE_NAME'] = 'huggingface-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)


# oauth config
oauth = OAuth(app)
huggingface = oauth.register(
    name='huggingface',
    client_id='4b0904ee....',
    client_secret='3b29d70f....',
    access_token_url='https://huggingface.co/oauth/token',
    access_token_params=None,
    authorize_url=f'https://huggingface.co/oauth/authorize',
    client_kwargs={'scope': 'inference-api'},
    server_metadata_url='https://huggingface.co/.well-known/openid-configuration'
)


@app.route('/')
@login_required
def hello_world():
    numbers = []
    for _ in range(4): # testing for actual token
        client = InferenceClient(
            model = "NousResearch/Hermes-3-Llama-3.1-8B",
            token = dict(session)['token']['access_token'],
            timeout = 60.0,
        )
        agent_reply = client.chat_completion(
            messages=[{"role": "user", "content": f"give me a random number between {random.randint(0, 50)} and {random.randint(50, 100)}, dont say anything else"}],
            max_tokens=200,
            stream=False,
        )
        numbers.append(agent_reply.choices[0].message.content)
    # uername = dict(session)['profile']
    return f'Hello, here are your numbers: {numbers}!'


@app.route('/login')
def login():
    huggingface = oauth.create_client('huggingface')  # create the hugginface oauth client
    redirect_uri = url_for('authorize', _external=True)
    return huggingface.authorize_redirect(redirect_uri)


@app.route('/authorize')
def authorize():
    huggingface = oauth.create_client('huggingface')  # create the hugginface oauth client
    token = huggingface.authorize_access_token()  # Access token from hugginface (needed to get user info)
    # user = oauth.huggingface.userinfo()  # uses openid endpoint to fetch user info
    session['token'] = token
    session.permanent = True  # make the session permanant so it keeps existing after broweser gets closed
    return redirect('/')


@app.route('/logout')
def logout():
    for key in list(session.keys()):
        session.pop(key)
    return redirect('/')


if __name__ == '__main__':
    app.run()