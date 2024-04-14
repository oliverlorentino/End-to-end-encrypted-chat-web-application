import os
import random
import string
import smtplib
import time
import hashlib
from PIL import Image, ImageDraw, ImageFont
from email.mime.text import MIMEText
from email.header import Header
import bcrypt
import requests

flag = True
last_time = time.time()


# lecture 5 slide 19
def bcrypt_encrypt(password):
    password_bytes = password.encode('utf-8')
    sha256 = hashlib.sha256(password_bytes).digest()
    salt = bcrypt.gensalt()
    bcrypt256 = bcrypt.hashpw(sha256, salt)

    return bcrypt256, salt


def bcrypt_validate(cipher, salt, password):
    cipher2 = password.encode('utf-8')
    sha2562 = hashlib.sha256(cipher2).digest()
    bcrypt2562 = bcrypt.hashpw(sha2562, salt)
    return cipher == bcrypt2562


def recover_key():  # length must larger than 24
    l = string.ascii_lowercase
    u = string.ascii_uppercase
    d = string.digits
    s = string.punctuation
    collet = l + u + d + s
    key = ''
    i = os.urandom(1)[0] % 17 + 24
    for ii in range(i):
        random_byte1 = os.urandom(1)[0]
        random_byte2 = os.urandom(1)[0]
        random_index = (random_byte1 * random_byte2) % len(l + u + d + s)
        key += collet[random_index]
    return key


def key_strength_sure(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    api = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(api)
    for line in response.text.splitlines():
        if suffix in line:
            return False
    return True


def can_send():
    global flag
    global last_time
    if flag:
        flag = False
        last_time = time.time()
        return True
    if time.time() - last_time > 60:
        last_time = time.time()
        return True
    return False


def generate_verification_code(length):
    digits = "0123456789"
    code = ''
    for i in range(length):
        randomness = os.urandom(1)[0]
        index = randomness % len(digits)
        code += digits[index]
    return code


def send_verification_email(receive_mail):
    # reused code from my repository:
    # https://github.com/oliverlorentino/COMP3211_GroupProject_Year3Sem1

    verification_code = generate_verification_code(6)
    global smtpObj
    message = MIMEText(verification_code, 'plain', 'utf-8')
    message['From'] = Header("admin", 'utf-8')
    message['To'] = Header("user", 'utf-8')

    # subject
    subject = 'Validation code' \
              '' \
              '' \
              '' \
              ''
    message['Subject'] = Header(subject, 'utf-8')

    try:
        # SMTP
        smtpObj = smtplib.SMTP('smtp.gmail.com', 587)  # SMTP service
        smtpObj.starttls()  # safe connects TLS
        smtpObj.login('oliverlorentino@gmail.com', 'jcfl djiv mgjn ytju')  # Application password of the GMAIL account
        smtpObj.sendmail('oliverlorentino@gmail.com', receive_mail, message.as_string())  # send mail
    except smtplib.SMTPException as e:
        print("Error: ；mail send fail", e)
    finally:
        smtpObj.quit()

    return verification_code





