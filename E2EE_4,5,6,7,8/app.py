

from flask import Flask, request, render_template, redirect, url_for, flash

app = Flask(__name__, static_folder='static',
            template_folder='templates')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        # finish E2EE
        if username == 'admin' and password == 'password':
            return redirect(url_for('chat'))
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/chat', methods=['GET', 'POST'])
def chat():
    return render_template('chat.html')

@app.route('/')
def home():
    return render_template('home.html')





#**E2EE_5**#

from flask import jsonify
#定义一个端点api来进行数据的处理返回
@app.route('/fetch_messages')
def fetch_messages():
    # 这里需要实现获取消息历史的逻辑
    # 假设已经有了方法来获取消息历史，例如从数据库中
    user_id = request.args.get('user_id')  # 通过查询参数传递用户ID
    messages = get_messages_for_user(user_id)  # 获取该用户的消息历史
    return jsonify(messages=messages)

#我需要从数据库中进行查询
#Message为数据库的名称
def get_messages_for_user(user_id):
    messages = Message.query.filter(
        (Message.sender_id == user_id) | (Message.receiver_id == user_id)
    ).order_by(Message.timestamp.asc()).all()

    # 将消息转换为字典列表以便进行JSON化
    messages_list = [{
        'id': message.id,
        'sender_id': message.sender_id,
        'receiver_id': message.receiver_id,
        'content': message.content,
        'timestamp': message.timestamp.isoformat()
    } for message in messages]
    return messages_list

#**E2EE_8**#
@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()

    # 对于加密消息，直接存储或转发，不进行解密
    if data['type'] == 'msg':
        # 这里应该是将加密消息存储到数据库或转发给接收者的逻辑
        store_or_forward_encrypted_message(data)
        return jsonify({'status': 'success', 'message': 'Message received'})

    return jsonify({'status': 'error', 'message': 'Invalid message type'})

def store_or_forward_encrypted_message(data):
    # 这里实现将加密消息存储到数据库或转发给接收者的逻辑
    return None


if __name__ == '__main__':

    app.run(host='127.0.0.1', port=61117)
