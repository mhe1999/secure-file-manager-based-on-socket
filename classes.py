import os
import rsa
import json
import base64
from Crypto.Cipher import AES



class cryptography():
    def __init__(self, server_pubkey):
        self.server_pubkey = server_pubkey

    def encrypt_RSA(self, message, key):             # message : string, key : rsa.PublicKey default = server_pubkey
        return rsa.encrypt(message.encode(), self.server_pubkey)    # returns a 'byte' type of encrypted message

    def decrypt_RSA(self, encrypted_message, key): # encrypted_message : 'byte' type, key : rsa.PrivateKey
        return rsa.decrypt(encrypted_message, key).decode()        # returns a string of decrypted message

    def create_session_key(self):
        self.session_key = os.urandom(32)
        return self.session_key   # returns a 256 bit 'byte' type

    # def establish_session_key(self, server_pubkey):
    #     self.session_key = self.create_session_key()
    #     socket.send_session_key(session_key = self.session_key,
    #                             server_pubkey=server_pubkey)

    def encrypt_AES(self, plaintext):
        cipher = AES.new(self.session_key,AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode()) # encryte data
        return ciphertext, nonce

    def decrypt_AES(self, message_bytes, nonce):
        print('decrypting data...')
        cipher = AES.new(self.session_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(message_bytes)               # decrype message with session key and nonce
        plaintext = plaintext.decode()
        return plaintext

    def base64_encode(self, message_bytes):
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        return base64_message

    def base64_decode(self, base64_message):
        base64_bytes = base64_message.encode('ascii')
        message_bytes = base64.b64decode(base64_bytes)
        return message_bytes

class socket_conn(cryptography):
    def __init__(self, conn, server_pubkey):
        super().__init__(server_pubkey = server_pubkey)
        self.conn = conn

    def send_session_key(self):
        self.create_session_key()
        session_key_dic = {'type' : 'session_key', 'value' : self.base64_encode(self.session_key)}
        session_key_json = json.dumps(session_key_dic)
        session_key_json_encrytped_RSA = self.encrypt_RSA(session_key_json, key=self.server_pubkey)
        # print('XXXX    ',session_key_json_encrytped_RSA, '\n')
        self.conn.sendall(session_key_json_encrytped_RSA)

    def recieve_session_key(self, session_key_json_encrytped_RSA):
        # print('XXXX    ',session_key_json_encrytped_RSA, '\n')
        session_key_json = self.decrypt_RSA(session_key_json_encrytped_RSA, key = self.server_privkey)
        session_key_dic = json.loads(session_key_json)
        self.session_key = self.base64_decode(session_key_dic['value'])

    def send_message(self, message, **kwargs):
        encrypted_message, nonce = self.encrypt_AES(message)
        encrypted_message_base64 = self.base64_encode(encrypted_message)
        nonce_base64 = self.base64_encode(nonce)
        encrypted_message_dic = {'encrypted_message' : encrypted_message_base64 ,
                                  'nonce' : nonce_base64}
        encrypted_message_json = json.dumps(encrypted_message_dic)
        self.conn.sendall(encrypted_message_json.encode())

    def recieve_message(self, encrypted_message_json):
        message_json = json.loads(encrypted_message_json.decode())  # message_json = {'encrypted_message' : aksdlbfvmnsznasfdfb, 'nonce' : mnfmq}
        encrypted_message_base64 = message_json['encrypted_message']
        nonce_base64 = message_json['nonce']
        encrypted_message = self.base64_decode(encrypted_message_base64)
        nonce = self.base64_decode(nonce_base64)
        message = self.decrypt_AES(encrypted_message, nonce) # message = {'type' : login, ...} --- json
        self.recieve_message_handler(message)

    def recieve_message_handler(self, message_json): # message_json = {'type' : login, ...} ---> json
        message = json.loads(message_json)  # message = {'type' : login, ...} ---> dict
        if message['type'] == 'register':
            self.handle_register_command()
        else:
            print('not vaild')

    def handle_register_command(self):
        print('in register')

    def send_register(self, uname, password, conf_label, integrity_label):
        dic_message = {'type' : 'registe',
                       'uname' : uname,
                       'password' : password,
                       'conf_label' : conf_label,
                       'integrity_label' : integrity_label}
        json_message = json.dumps(dic_message)
        self.send_message(json_message)

class server(socket_conn):
    def __init__(self, conn, server_pubkey, server_privkey):
        super().__init__(conn, server_pubkey)
        self.server_privkey = server_privkey


class clients():
    pass

class files():
    pass



# TODO: calculate session key CHECK
# TODO: send session key CHECK
# TODO: recieve session key CHECK
# TODO: encryption text
# TODO: decryption text
# TODO: send message
# TODO: recieve message
# TODO: encryption file
# TODO: decryption file
# TODO: send file
# TODO: recieve file
# TODO: create database
# TODO: register
# TODO: login
# TODO: put
# TODO: read
# TODO: write
# TODO: get
# TODO: BLP
# TODO: Biba
# TODO: calculate hash
# TODO: check hash
# TODO: weak password
# TODO: base64 encode
# TODO: base64 decode
# TODO: hash passwords
# TODO: backoff
# TODO: logging
# TODO: analyse logs
# TODO: DAC
# TODO: Honeypot
