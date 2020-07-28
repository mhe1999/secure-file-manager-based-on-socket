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
        print(self.base64_encode(session_key_json_encrytped_RSA),'\n\n')
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

    def send_message_handler(self, message):
        message_array = message.split()
        type = message_array[0]
        if type == 'register':
            self.send_register_command(unmae = message_array[1],
                                       password = message_array[2],
                                       conf_label = message_array[3],
                                       integrity_label = message_array[4])

        elif type == 'login':
            self.send_login_command(   unmae = message_array[1],
                                       password = message_array[2])

        elif type == 'put':
            self.send_put_command(     filename = message_array[1],
                                       conf_label = message_array[3],
                                       integrity_label = message_array[4])

        elif type == 'read':
            self.send_read_command(    filename = message_array[1])

        elif type == 'write':
            self.send_write_command(   filename = message_array[1],
                                       content = message_array[3])

        elif type == 'get':
            self.send_get_command(    filename = message_array[1])

        else:
            print('not valid input')

    def recieve_message_handler(self, message_json): # message_json = {'type' : login, ...} ---> json
        message = json.loads(message_json)  # message = {'type' : login, ...} ---> dict
        if message['type'] == 'register':
            self.handle_register_command()
        elif message['type'] == 'login':
            self.handle_login_command()
        elif message['type'] == 'put':
            self.handle_put_command()
        elif message['type'] == 'read':
            self.handle_read_command()
        elif message['type'] == 'write':
            self.handle_write_command()
        elif message['type'] == 'get':
            self.handle_get_command()
        else:
            print('not vaild')

    def handle_register_command(self):
        print('in register')

    def handle_login_command(self):
        print('in login')

    def handle_put_command(self):
        print('in put')

    def handle_read_command(self):
        print('in read')

    def handle_write_command(self):
        print('in write')

    def handle_get_command(self):
        print('in get')

    def send_register_command(self, uname, password, conf_label, integrity_label):
        dic_message = {'type' : 'register',
                       'uname' : uname,
                       'password' : password,
                       'conf_label' : conf_label,
                       'integrity_label' : integrity_label}
        json_message = json.dumps(dic_message)
        self.send_message(json_message)

    def send_login_command(self, uname, password):
        dic_message = {'type' : 'login',
                       'uname' : uname,
                       'password' : password}
        json_message = json.dumps(dic_message)
        self.send_message(json_message)

    def send_put_command(self, filename, conf_label, integrity_label):
        dic_message = {'type' : 'put',
                       'filename' : filename,
                       'conf_label' : conf_label,
                       'integrity_label' : integrity_label}
        json_message = json.dumps(dic_message)
        self.send_message(json_message)

    def send_read_command(self, filename):
        dic_message = {'type' : 'read',
                       'filename' : filename}
        json_message = json.dumps(dic_message)
        self.send_message(json_message)

    def send_write_command(self, filename, content):
        dic_message = {'type' : 'write',
                       'filename' : filename,
                       'content' : content}
        json_message = json.dumps(dic_message)
        self.send_message(json_message)

    def send_get_command(self, filename):
        dic_message = {'type' : 'get',
                       'filename' : filename}
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
# TODO: encryption text CHECK
# TODO: decryption text CHECK
# TODO: send message CHECK
# TODO: recieve message CHECK
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
