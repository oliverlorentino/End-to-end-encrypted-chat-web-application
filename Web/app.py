import os

from flask import Flask, request, render_template, redirect, url_for, flash
import time

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


if __name__ == '__main__':

    app.run(host='127.0.0.1', port=61117)
