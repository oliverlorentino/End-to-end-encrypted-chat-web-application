from datetime import datetime

from flask import Flask, request, render_template, redirect, url_for, flash
from flask_cors import CORS
from Web.database import get_mysql_connection
from Web.util import send_verification_email, can_send, gen_captcha_image

app = Flask(__name__, static_folder='./static')
CORS(app)

global_dict = {}
picture_code = ''


@app.route('/register', methods=['POST'])
def register():
    global global_dict
    email = request.form['registerEmail']
    if email in global_dict:
        return render_template('login.html')
    flag = can_send()
    if flag:
        code = send_verification_email(email)
        global_dict[email] = code
        return render_template('registerCode.html')
    return render_template('login.html')


@app.route('/registerCode', methods=['POST'])
def register_code():
    email = request.form['email']
    code = request.form['code']
    global global_dict
    if global_dict[email] == code:
        return render_template('userInfo.html')
    return render_template('login.html')


@app.route('/userInfo', methods=['POST'])
def user_info():
    user_name = request.form['userName']
    password = request.form['password']
    connection = get_mysql_connection()
    cursor = connection.cursor()
    save_sql = "INSERT INTO users (username, password, created_at) VALUES (%s, %s,%s);"
    cursor.execute(save_sql, (user_name, password, datetime.now()))
    connection.commit()
    connection.close()
    return render_template('chat.html')


@app.route('/code', methods=['POST'])
def code():
    email = request.form['email']
    code = request.form['code']
    global global_dict
    if global_dict[email] == code:
        print("test-----------")
        return render_template('chat.html')
    return render_template('login.html')


@app.route('/email', methods=['POST'])
def email():
    flag = can_send()
    if flag:
        email = request.form['email']
        code = send_verification_email(email)
        global_dict[email] = code
        return render_template('code.html')
    return render_template('email.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    global picture_code
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        captcha = request.form['captcha']
        if captcha != picture_code:
            return render_template('login.html')
        connection = get_mysql_connection()
        cursor = connection.cursor()

        query = 'SELECT * FROM users WHERE username = %s AND password = %s'
        params = (username, password)
        cursor.execute(query, params)

        # 获取查询结果的数量
        result = cursor.fetchall()
        result_count = len(result)
        if result_count == 0:
            cursor.close()
            connection.close()
            return redirect(url_for('login'))
        cursor.close()
        connection.close()
        return render_template('email.html')
    picture_code = gen_captcha_image()
    return render_template('login.html')


@app.route('/chat', methods=['GET', 'POST'])
def chat():
    return render_template('chat.html')


@app.route('/')
def home():
    return render_template('home.html')


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=61117)
