import random
import smtplib
import ssl
import time
from email.message import EmailMessage
import hashlib
from PIL import Image, ImageDraw, ImageFont

flag = True
last_time = time.time()


def sha256_encrypt(text):
    # 创建SHA256哈希对象
    sha256_hash = hashlib.sha256()

    # 更新哈希对象的内容
    sha256_hash.update(text.encode('utf-8'))

    # 获取加密结果
    encrypted_text = sha256_hash.hexdigest()

    return encrypted_text


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
    EMAIL_ADDRESS = '2968632149@qq.com'  # 换成你的邮箱地址
    EMAIL_PASSWORD = 'fhdqpzwpgenjdgid'
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


# 随机生成4位验证码
def random_captcha_text(char_set, captcha_size=4):
    captcha_text = ''
    for i in range(captcha_size):
        c = random.choice(char_set)
        captcha_text += c
    return captcha_text


# 下载验证码图片
def gen_captcha_image():
    image = Image.new('RGB', (100, 50), (255, 255, 255))
    font = ImageFont.truetype('arial.ttf', 40)
    draw = ImageDraw.Draw(image)

    # 绘制字符串
    captcha_text = random_captcha_text('0123456789ABCDEFGHIJKLMNPQRSTUVWXYZ', 4)
    draw.text((10, 10), captcha_text, font=font, fill=(0, 0, 255))

    # 添加干扰线
    for i in range(5):
        x1 = random.randint(0, 100)
        y1 = random.randint(0, 100)
        x2 = random.randint(0, 100)
        y2 = random.randint(0, 100)
        draw.line((x1, y1, x2, y2), fill=(0, 0, 255))

    # 保存生成的验证码图片
    image.save('../Web/static/captcha.jpg', 'jpeg')

    return captcha_text


