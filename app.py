from flask import Flask, redirect, url_for, session, abort, request
import requests
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
huggingface = oauth.register(
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
            # try:
            #     client = InferenceClient(
            #         model = "NousResearch/Hermes-3-Llama-3.1-8B",
            #         # token = "hf_1asduioaiusdiu",
            #         token = dict(session)['user_token']['access_token'],
            #         timeout = 60.0,
            #     )
            # except:
            # print(f"token={session["user_token"]}")
            # huggingface = oauth.create_client('huggingface')  # create the hugginface oauth client
            # # if not huggingface:
            # #     abort(404)
            # # print(dir(huggingface))
            # # print(dir(oauth))
            # new_token = huggingface.fetch_access_token(
            #     token_url='https://huggingface.co/oauth/token',
            #     refresh_token=session['user_token']['refresh_token'],
            #     grant_type='refresh_token',
            #     scope='https://huggingface.co'
            # )

            # huggingface = oauth.create_client('huggingface')  # create the hugginface oauth client
            # if not huggingface:
            #     abort(404)
            # token = huggingface.authorize_access_token(grant_type='refresh_token', refresh_token=session['user_token']['refresh_token'])  # Access token from hugginface (needed to get user info)
            # token = huggingface.authorize_access_token()  # Access token from hugginface (needed to get user info)
            # session['user_token'].update(token)
            # print(f"token={session["user_token"]}")
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
    for _ in range(4): # testing for actual token
        client = InferenceClient(
            model = "NousResearch/Hermes-3-Llama-3.1-8B",
            # token = "hf_1asduioaiusdiu",
            token = dict(session)['user_token']['access_token'],
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
    if not huggingface:
        abort(404)
    redirect_uri = url_for('authorize', _external=True)
    return huggingface.authorize_redirect(redirect_uri)


@app.route('/authorize')
def authorize():
    print("##################333")
    print(request.data)
    huggingface = oauth.create_client('huggingface')  # create the hugginface oauth client
    if not huggingface:
        abort(404)
    token = huggingface.authorize_access_token()  # Access token from hugginface (needed to get user info)
    print(f"{token=}")
    user = oauth.huggingface.userinfo()  # uses openid endpoint to fetch user info
    print(f"{user=}")
    session['user_token'] = token
    session.permanent = True  # make the session permanant so it keeps existing after broweser gets closed
    return redirect('/')


@app.route('/revoke_token')
def revoke_token():
    token = session.get('user_token')
    if token:
        token_url = 'https://huggingface.co/oauth/revoke'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {
            'token': token['access_token'],
            'token_type_hint': 'access_token',
            'client_id': '4b0904ee-f186-4259-9878-3d082fd57e20',
            'client_secret': '3b29d70f-7566-468d-beb0-d7065159d16a'
        }
        response = requests.post(token_url, headers=headers, data=data)
        print(response)
        if response.status_code == 200:
            session.pop('user_token', None)
            return 'Token revoked successfully!'
        else:
            return 'Error revoking token', 400
    return 'No token to revoke', 400


@app.route('/logout')
def logout():
    for key in list(session.keys()):
        session.pop(key)
    session.clear()
    return redirect('/')


if __name__ == '__main__':
    app.run()