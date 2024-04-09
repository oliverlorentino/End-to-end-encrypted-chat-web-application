import smtplib
import random
import ssl
import time

from email.message import EmailMessage

flag = True
last_time = time.time()


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
    # 生成指定长度的随机验证码
    digits = "0123456789"
    code = "".join(random.choice(digits) for _ in range(length))
    return code


def send_verification_email(receive_mail):
    # 生成验证码
    verification_code = generate_verification_code(6)
    EMAIL_ADDRESS = '2171649454@qq.com'  # 换成你的邮箱地址
    EMAIL_PASSWORD = 'ydmhlwplxsqkdjje'
    smtp = smtplib.SMTP('smtp.qq.com', 25)
    context = ssl.create_default_context()
    sender = EMAIL_ADDRESS  # 发件邮箱
    receiver = [receive_mail]
    # 收件邮箱
    subject = "验证码"
    # 这里我调用了自己的接口，如果不需要直接将body改为 body = '正文'
    body = verification_code
    msg = EmailMessage()
    msg['subject'] = subject  # 邮件主题
    msg['From'] = sender
    msg['To'] = receiver
    msg.set_content(body)  # 邮件内容

    with smtplib.SMTP_SSL("smtp.qq.com", 465, context=context) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)

    return verification_code
