from datetime import datetime

import requests
from flask import Flask, request, render_template, redirect, url_for, session, flash
from util import send_verification_email, can_send, bcrypt_encrypt, bcrypt_validate, recover_key, \
    key_strength_sure
import pymysql
from flask_session import Session
import yaml
import base64
from flask_wtf.csrf import CSRFProtect
from flask import jsonify

app = Flask(__name__, static_folder='./static')

# Configure secret key and Flask-Session
app.config.from_pyfile('configure.py')
csrf = CSRFProtect(app)
app.config['SESSION_TYPE'] = 'filesystem'  # Options: 'filesystem', 'redis', 'memcached', etc.
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True  # To sign session cookies for extra security
app.config['SESSION_FILE_DIR'] = './sessions'  # Needed if using filesystem type

with open('db.yaml', 'r') as file:
    db_config = yaml.safe_load(file)


def get_db_connection():
    connection = pymysql.connect(host=db_config['mysql_host'],
                                 user=db_config['mysql_user'],
                                 password=db_config['mysql_password'],
                                 db=db_config['mysql_db'],
                                 charset='utf8mb4',
                                 cursorclass=pymysql.cursors.DictCursor)
    return connection


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        emails = request.form['registerEmail']
        recaptcha_response = request.form['g-recaptcha-response']

        secret_key = '6Lcf-bgpAAAAAAFoEEUTiD-Cm9GxnPFIvA40YVNG'
        data = {
            'secret': secret_key,
            'response': recaptcha_response
        }
        verify_response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
        verify_result = verify_response.json()

        if not verify_result.get('success', False):
            flash('Invalid reCAPTCHA')
            return render_template('login.html')
        connection = get_db_connection()
        cur = connection.cursor()
        query = 'SELECT * FROM users WHERE email = %s'
        params = (emails,)
        cur.execute(query, params)
        result = cur.fetchone()
        connection.close()
        if result is not None:
            flash("Already exit email")
            return render_template('login.html')
        flag = can_send()  # you can only use this per 60s
        if flag:
            vcode = send_verification_email(emails)
            session['email'] = emails
            session['register_code'] = vcode
            return redirect(url_for('registerCode'))
        else:
            flash("frequent asking wait and sign up")

    return render_template('login.html')


@app.route('/registerCode', methods=['POST', 'GET'])
def registerCode():
    if 'register_code' not in session:
        return redirect(url_for('register'))
    if request.method == 'POST':
        vcode = request.form['code']
        if session['register_code'] == vcode:
            session['code_validate'] = True
            return redirect(url_for('userInfo'))
        else:
            flash("Invalid validation code !")

    return render_template('registerCode.html')


@app.route('/userInfo', methods=['POST', 'GET'])
def userInfo():
    if 'code_validate' not in session:
        return redirect(url_for('registerCode'))
    if request.method == 'POST':
        user_name = request.form['userName']
        password = request.form['password']
        confirm_password = request.form['confirmpassword']

        connection = get_db_connection()
        cur = connection.cursor()
        query = 'SELECT * FROM users WHERE username = %s'
        params = (user_name,)
        cur.execute(query, params)
        result = cur.fetchone()
        connection.close()
        if result is not None:
            flash("Already exit username")
            return render_template('userInfo.html')

        if not key_strength_sure(password):
            flash("weak password")
            return render_template('userInfo.html')

        if password != confirm_password:
            flash('Passwords not match. Try again!')
            return render_template('userInfo.html')
        cipher, salt = bcrypt_encrypt(password)
        salt = base64.b64encode(salt).decode('utf-8')
        cipher = base64.b64encode(cipher).decode('utf-8')
        connection = get_db_connection()
        cur = connection.cursor()
        save_sql = "INSERT INTO users (username, email, created_at) VALUES (%s, %s,%s);"
        cur.execute(save_sql, (user_name, session['email'], datetime.now()))
        connection.commit()

        cur.execute('SELECT LAST_INSERT_ID()')
        user_id = cur.fetchone()['LAST_INSERT_ID()']

        save_sql2 = "INSERT INTO user_passwords (user_id,password_cipher,salt,recovery_key) VALUES (%s,%s, %s,%s);"
        recoverKey = recover_key()
        cur.execute(save_sql2, (user_id, cipher, salt, recoverKey))
        connection.commit()
        connection.close()
        session.pop('code_validate', None)
        session['chat_allow'] = True
        session['username'] = user_name
        flash("keep your recoverey key: " + recoverKey)
        return redirect(url_for('chat'))

    return render_template('userInfo.html')


@app.route('/code', methods=['GET', 'POST'])
def code():
    if 'code_permit' not in session:
        return redirect(url_for('email'))

    if request.method == 'GET':
        return render_template('code.html')

    else:
        user_code = request.form['code']

        if 'email_code' in session and session['email_code'] == user_code:

            session['chat_allow'] = True
            return redirect(url_for('chat'))
        else:
            flash('Verification code is incorrect. Please try again.')
            return render_template('code.html')


@app.route('/email', methods=['GET', 'POST'])
def email():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        email = request.form['email']
        if not can_send():
            flash('frequent asking please wait 60s')
            return render_template('email.html')
        connection = get_db_connection()
        cur = connection.cursor()
        query = 'SELECT email FROM users WHERE username = %s'
        params = (session['username'],)
        cur.execute(query, params)
        result = cur.fetchone()
        if result is None:
            flash(session['username'])
            connection.close()
            return render_template('email.html')

        if result['email'] != email:
            connection.close()
            flash("unmatched email")
            return render_template('email.html')

        vcode = send_verification_email(email)
        session['email'] = email
        session['email_code'] = vcode
        session['code_permit'] = True
        connection.close()
        return redirect(url_for('code'))
    else:
        return render_template('email.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        recaptcha_response = request.form['g-recaptcha-response']

        secret_key = '6Lcf-bgpAAAAAAFoEEUTiD-Cm9GxnPFIvA40YVNG'
        data = {
            'secret': secret_key,
            'response': recaptcha_response
        }
        verify_response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
        verify_result = verify_response.json()

        if not verify_result.get('success', False):
            flash('Invalid reCAPTCHA')
            return render_template('login.html')

        connection = get_db_connection()
        cur = connection.cursor()
        query = 'SELECT user_id FROM users WHERE username = %s'
        params = (username,)
        cur.execute(query, params)

        # get number of query, fetchcone I think works the same since db is small
        result = cur.fetchone()
        if result is None:
            flash('Invalid username')
            connection.close()
            return render_template('login.html')
        user_id = result['user_id']
        query2 = 'SELECT password_cipher,salt FROM user_passwords WHERE user_id = %s'
        params = (user_id,)
        cur.execute(query2, params)
        result2 = cur.fetchone()
        password_cipher = result2['password_cipher']
        salt = result2['salt']
        salt = base64.b64decode(salt.encode('utf-8'))
        password_cipher = base64.b64decode(password_cipher.encode('utf-8'))
        connection.close()
        if not bcrypt_validate(password_cipher, salt, password):
            flash("wrong password")
            return render_template('login.html')

        session['username'] = username
        return redirect(url_for('email'))
    return render_template('login.html')


@app.route('/forget', methods=['POST', 'GET'])
def forget():
    if request.method == 'POST':
        username = request.form['username']
        recoverKey = request.form['recoverKey']
        email1 = request.form['email']
        connection = get_db_connection()
        cur = connection.cursor()
        query = 'SELECT user_id,email FROM users WHERE username = %s'
        params = (username,)
        cur.execute(query, params)
        result = cur.fetchone()
        if result is None:
            flash('Username does not exist')
            return render_template('forget.html')
        user_id = result['user_id']
        email2 = result['email']
        if email2 != email1:
            flash('Unmatched email')
            return render_template('forget.html')
        query2 = 'SELECT recovery_key FROM user_passwords WHERE user_id = %s'
        params = (user_id,)
        cur.execute(query2, params)
        result2 = cur.fetchone()
        if result2['recovery_key'] != recoverKey:
            flash('Unmatched recovery_key')
            return render_template('forget.html')
        session['reset_username'] = username
        return redirect(url_for('reset'))
    return render_template('forget.html')


@app.route('/reset', methods=['POST', 'GET'])
def reset():
    if 'reset_username' not in session:
        return redirect(url_for('forget'))
    if request.method == 'POST':
        password = request.form['new_password']
        confirm_password = request.form['confirmpassword']

        connection = get_db_connection()
        cur = connection.cursor()
        query = 'SELECT user_id FROM users WHERE username = %s'
        params = (session['reset_username'],)
        cur.execute(query, params)
        result = cur.fetchone()
        user_id = result['user_id']

        if not key_strength_sure(password):
            connection.close()
            flash("weak password")
            return render_template('reset.html')

        if password != confirm_password:
            connection.close()
            flash('Passwords not match. Try again!')
            return render_template('reset.html')
        cipher, salt = bcrypt_encrypt(password)
        salt = base64.b64encode(salt).decode('utf-8')
        cipher = base64.b64encode(cipher).decode('utf-8')

        save_sql2 = "UPDATE user_passwords SET password_cipher = %s, salt = %s WHERE user_id = %s;"
        cur.execute(save_sql2, (cipher, salt, user_id))
        connection.commit()
        connection.close()
        session.pop('reset_username', None)
        flash('reset successfully, login again')
        return redirect(url_for('login'))
    return render_template('reset.html')


@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'chat_allow' not in session:
        return redirect(url_for('login'))

    return render_template('chat.html')


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    delete_user(session['username'])
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
def home():
    return render_template('home.html')


'''users = [
    {'userId': '1', 'name': 'Alice', 'publicKey': 'AlicePublicKey'},
    {'userId': '2', 'name': 'Bob', 'publicKey': 'BobPublicKey'}

]'''





def delete_user(username):
    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "DELETE FROM chat WHERE name = %s;"
        cursor.execute(sql, (username,))
        connection.commit()
        connection.close()


# 假设有一个全局变量来存储消息
# messages = []


@app.route('/users')
def get_users():
    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "SELECT * FROM chat;"
        cursor.execute(sql)
        results = cursor.fetchall()
        connection.close()
    return jsonify({'users': results})


@app.route('/send-public-key', methods=['POST'])
def receive_public_key():
    data = request.get_json()
    user_id = data.get('userId')
    public_key = data.get('publicKey')
    if not user_id or not public_key:
        return jsonify({'error': 'Missing userId or publicKey'}), 400
    username = session['username']
    if 'username' not in session:
        return jsonify({'error': 'no username'}), 400
    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "INSERT INTO chat (userId, name, publicKey) VALUES (%s, %s, %s) ON DUPLICATE KEY UPDATE name = VALUES(name), publicKey = VALUES(publicKey);"
        cursor.execute(sql, (user_id, username, public_key))
        connection.commit()
        connection.close()
    return jsonify({'success': 'Public key updated successfully'}), 200


@app.route('/receive-public-key', methods=['GET'])
def send_public_key():
    user_id = request.args.get('userId')
    # user = next((user for user in users if user['userId'] == user_id), None)
    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "SELECT * FROM chat WHERE userId = %s;"
        p = (user_id,)
        cursor.execute(sql, p)
        result = cursor.fetchone()
        connection.close()
    if result:
        return jsonify({'publicKey': result['publicKey']})
    else:
        return jsonify({'error': 'User not found'}), 404


@app.route('/fetch_messages')
def fetch_messages():
    last_message_id = request.args.get('last_message_id', type=int, default=0)
    peer_id = request.args.get('peer_id')
    '''
    filtered_messages = [
        msg for msg in messages
        if int(msg['message_id']) > last_message_id
    ]'''

    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "SELECT * FROM messages WHERE message_id > %s;"
        cursor.execute(sql, (last_message_id,))
        results = cursor.fetchall()

    return jsonify({'messages': results})


@app.route('/send_message', methods=['POST'])
def send_message():
    # 解析请求体中的 JSON 数据
    data = request.get_json()
    if not data or 'receiver_id' not in data or 'message_text' not in data:
        return jsonify({'error': 'Missing required parameters'}), 400

    # 创建消息对象，包括 sender_id, receiver_id, 和 message_text
    # 假设 sender_id 从认证系统或会话中获取
    # 静态分配为示例，实际应用中应该从会话或令牌中获取
    '''message = {
        'message_id': len(messages) + 1,  # 简单递增作为 message_id
        'sender_id': data['sender_id'],
        'receiver_id': data['receiver_id'],
        'message_text': data['message_text']
    }
    messages.append(message)'''

    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "INSERT INTO messages (sender_id, receiver_id, message_text) VALUES (%s, %s, %s);"
        cursor.execute(sql, (data['sender_id'], data['receiver_id'], data['message_text']))
        connection.commit()
        connection.close()

    # 返回成功响应
    return jsonify({'message': 'Message sent successfully'}), 201


@app.route('/erase_chat', methods=['POST'])
def erase_chat():
    data = request.get_json()
    peer_id = data.get('peer_id')
    
    if peer_id is None:
        return jsonify({'error': 'Missing peer_id'}), 400

    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = """
        DELETE FROM messages WHERE sender_id = %s OR receiver_id = %s;
        """
        affected_rows = cursor.execute(sql, (peer_id, peer_id))
        connection.commit()
        connection.close()

    return jsonify({'success': True, 'message': f'Erased {affected_rows} messages with peer_id {peer_id}.'})

key_updates = {}

@app.route('/send-key-update', methods=['POST'])
def handle_key_update():
    data = request.get_json()
    user_id = data.get('userId')
    if not user_id or 'keyUpdateMessage' not in data or 'oldMac' not in data or 'newMac' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    if 'username' not in session:
        return jsonify({'error': 'no username'}), 400

    key_updates[user_id] = {
        'keyUpdateMessage': data['keyUpdateMessage'],
        'oldMac': data['oldMac'],
        'newMac': data['newMac']
    }

    return jsonify({'success': 'Key update received'}), 200

@app.route('/fetch-key-update', methods=['GET'])
def fetch_key_update():
    user_id = request.args.get('userId')
    if not user_id:
        return jsonify({'error': 'Missing userId'}), 400

    # 从内存中检索密钥更新信息
    key_update_info = key_updates.get(user_id)
    if key_update_info:
        return jsonify(key_update_info)
    else:
        return jsonify({'error': 'No key update available'}), 404

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=61117)
