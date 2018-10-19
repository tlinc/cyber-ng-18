import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from stegano import lsb

from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = '/home/pi/Destktop/StegyCat/pics'

app = Flask(__name__, template_folder='templates')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def stego_in(ct, mac, nonce, picture):
    secret_message = {'msg': ct, 'nc': nonce, 'mc': mac}
    secret_message = str(secret_message)
    secret_image = lsb.hide('./pics/cat.png', secret_message)
    secret_image.save('./secretpics/secret_image.png')
    
    #print(var)


def stego_out(picture):
    hidden_ct = lsb.reveal(picture)
    #Parse here
    dt = eval(hidden_ct)
    message = dt['msg']
    nonce = dt['nc']
    mac = dt['mc']

    return message, nonce, mac


def decrypt(message, nonce, mac):
    f = open("key.txt", "r")
    string = f.read()
    dict = eval(string)
    key = dict['key']
    #ctlength = len(hidden_ct)
    #nonce = hidden_ct[ctlength:]
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=backend)
    decryptor = cipher.decryptor()
    msg = decryptor.update(message) + decryptor.finalize()
    print(msg)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(msg)
    cmpmac = digest.finalize()
    if mac != cmpmac:
        return 0
    else:
        return msg


def encrypt(msg, email):
    backend = default_backend()

    # Salts should be randomly generated

    salt = os.urandom(16)
    nonce = os.urandom(16)
    # derive

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(email.encode('UTF-8'))
    dict = {'key': key}
    f = open("key.txt" ,"w")
    f.write(str(dict))
    # verify

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    #kdf.verify(b"tim@gmail.com", key)

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(msg.encode('UTF-8')) + encryptor.finalize()

    #newct = ct + nonce

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(msg.encode('UTF-8'))
    mac = digest.finalize()
    return ct, mac, nonce

@app.route('/')
def index():
    return render_template('create.html')


@app.route('/get-info', methods=['POST', 'GET'])
def get_info():
    if request.method == 'POST':
        result = request.form
        picture = result.getlist('file')
        msg = result.get('message')
        email = result.get('email')
        #write key(email) to file 
        msg, mac, nonce = encrypt(msg, email)
        stego_in(msg, mac, nonce, picture)
        #redirect(url_for('encrypt', msg=msg, email=email))
        return render_template("decrypt.html")


@app.route('/get_decrypt', methods=['POST', 'GET'])
def get_decrypt():
    if request.method == 'POST':
        # picture = request.form['file']
        # filename = secure_filename(file.filename)
        # file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        message, nonce, mac = stego_out('./secretpics/secret_image.png')
        #get key from file
        pt = decrypt(message, nonce, mac)
        return render_template("display.html", message = pt)
        #read key from file 


if __name__ == '__main__':
    app.run(debug=True)
    
