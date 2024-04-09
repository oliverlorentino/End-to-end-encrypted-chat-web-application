import os
import base64
from flask import Flask, request, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

public_keys = {}
encryption_parameters_store = {}

#定义根Endpoint
@app.route('/')
def index():
    return "Genshin Impact, Start!"

#定义用于密钥生成的Endpoint（利用椭圆曲线算法)
@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP384R1()) #生成椭圆曲线私钥
    public_key = private_key.public_key() #基于私钥生成公钥
    
    #将公钥转换成PEM格式储存
    public_jwk = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    user_id = request.json['user_id']  #从POST请求中提取Userid
    public_keys[user_id] = public_jwk  #储存公钥（基于userid索引）
    return jsonify({'public_key': public_jwk}) #返回Json相应

#定义用于检索其它用户密钥的Endpoint
@app.route('/get_peer_public_key', methods=['POST'])
def get_peer_public_key():
    peer_id = request.json['peer_id'] #从POST中提取peerid
    peer_public_key = public_keys.get(peer_id) #基于id，从之前定义的字典中提取相应公钥
    
    if peer_public_key:
        return jsonify({'peer_public_key': peer_public_key})
    else:
        return jsonify({'error': 'Public key not found'}), 404

#定义用于派生密钥的端点
@app.route('/derive_keys', methods=['POST'])

#接受派生密钥，派生出加密和MAC密钥
def handle_derive_keys():
    data = request.get_json()
    #从POST请求中提取共享钥对、盐、用户id
    shared_key = bytes.fromhex(data['shared_key'])
    salt = bytes.fromhex(data['salt'])
    user1 = data['user1']
    user2 = data['user2']
    
    #执行用于派生的函数
    keys = derive_keys(shared_key, salt, user1, user2)

    return jsonify({
        'encrypt_key_12': keys[0].hex(),
        'encrypt_key_21': keys[1].hex(),
        'mac_key_12': keys[2].hex(),
        'mac_key_21': keys[3].hex()
    })

#执行HKDF算法
def derive_keys(shared_key, salt, user1, user2):
    # 为每个密钥派生操作创建独立的HKDF对象（使用SHA-256算法）
    hkdf_encrypt_12 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=f'CHAT_KEY_{user1}to{user2}'.encode(),
        backend=default_backend()
    )
    encrypt_key_12 = hkdf_encrypt_12.derive(shared_key)

    hkdf_encrypt_21 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=f'CHAT_KEY_{user2}to{user1}'.encode(),
        backend=default_backend()
    )
    encrypt_key_21 = hkdf_encrypt_21.derive(shared_key)

    hkdf_mac_12 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=f'CHAT_MAC_{user1}to{user2}'.encode(),
        backend=default_backend()
    )
    mac_key_12 = hkdf_mac_12.derive(shared_key)

    hkdf_mac_21 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=f'CHAT_MAC_{user2}to{user1}'.encode(),
        backend=default_backend()
    )
    mac_key_21 = hkdf_mac_21.derive(shared_key)

    return (
        encrypt_key_12,
        encrypt_key_21,
        mac_key_12,
        mac_key_21
    )

store = {}

#定义加密消息端点
@app.route('/encrypt_message', methods=['POST'])
#处理消息，返回相应变量
def handle_encrypt_message():

    #从客户端的POST请求中提取JSON消息，再进一步提取加密密钥、MAC密钥、关联数据和iv
    data = request.get_json()
    message = data['message']
    key_encryption = bytes.fromhex(data['key_encryption'])
    key_mac = bytes.fromhex(data['key_mac'])
    associated_data = data['associated_data'].encode()
    iv = bytes.fromhex(data['iv'])

    #调用加密函数，传递相关参数
    ciphertext, mac_tag = encrypt_message(message, key_encryption, key_mac, associated_data, iv)

    message_id = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
    store[message_id] = {
        'key_encryption': key_encryption.hex(),
        'key_mac': key_mac.hex(),
        'associated_data': associated_data.decode('utf-8'),
        'iv': iv.hex(),
        'mac_tag': mac_tag.hex()
    }

    return jsonify({
        'ciphertext': ciphertext.hex(),
        'mac_tag': mac_tag.hex(),
        'iv': iv.hex(),
        'message_id': message_id,
    })

#执行AES-GCM算法以加密
def encrypt_message(message, key_encryption, key_mac, associated_data, iv):
    #基于先前的加密密钥创建AESGCM对象
    aesgcm = AESGCM(key_encryption)
    #得到密文
    ciphertext = aesgcm.encrypt(iv, message.encode(), associated_data)
    #利用mac密钥创建HMAC对象，获得最终mac标签
    h = hmac.HMAC(key_mac, hashes.SHA256())
    h.update(iv)
    mac_tag = h.finalize()

    return ciphertext, mac_tag

#定义解密消息端点
@app.route('/decrypt_message', methods=['POST'])

#接受前面加密时返回的指标来处理消息
def handle_decrypt_message():
    try:
        data = request.get_json()
        message_id = data['message_id']
        ciphertext = bytes.fromhex(data['ciphertext'])
        params = encryption_parameters_store.get(message_id)
        if not params:
            raise ValueError("Invalid message ID")
        
        key_encryption = bytes.fromhex(data['key_encryption'])
        key_mac = bytes.fromhex(data['key_mac'])
        associated_data = data['associated_data'].encode()
        iv = bytes.fromhex(data['iv'])
        mac_tag = bytes.fromhex(data['mac_tag'])

        #获得明文
        plaintext = decrypt_message(ciphertext, key_encryption, key_mac, associated_data, iv, mac_tag)

        return jsonify({'plaintext': plaintext})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

#执行AES-GCM算法来解密
def decrypt_message(ciphertext, key_encryption, key_mac, associated_data, iv, mac_tag):
    aesgcm = AESGCM(key_encryption)
    plaintext = aesgcm.decrypt(iv, ciphertext, associated_data)
    
    return plaintext.decode()

if __name__ == '__main__':
    app.run(debug=True)