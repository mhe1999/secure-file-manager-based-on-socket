import os
import rsa
import json
import base64

class clients():
    pass

class files():
    pass

class AES_cryptography():
    pass

class RSA_cryptography():
    def __init__(self, server_pubkey):
        self.server_pubkey = server_pubkey

    def encrypt_RSA(self, message, key):             # message : string, key : rsa.PublicKey default = server_pubkey
        return rsa.encrypt(message.encode(), self.server_pubkey)    # returns a 'byte' type of encrypted message

    def decrypt_RSA(self, encrypted_message, key): # encrypted_message : 'byte' type, key : rsa.PrivateKey
        return rsa.decrypt(encrypted_message, key).decode()        # returns a string of decrypted message

    def create_session_key(self):
        self.session_key = os.urandom(32)
        return self.session_key   # returns a 256 bit 'byte' type

    def establish_session_key(self, server_pubkey):
        self.session_key = self.create_session_key()
        socket.send_session_key(session_key = self.session_key,
                                server_pubkey=server_pubkey)

    def base64_encode(self, message_bytes):
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        return base64_message

    def base64_decode(self, base64_message):
        base64_bytes = base64_message.encode('ascii')
        message_bytes = base64.b64decode(base64_bytes)
        return message_bytes


class socket_conn(RSA_cryptography):
    def __init__(self, conn, server_pubkey):
        super().__init__(server_pubkey = server_pubkey)
        self.conn = conn

    def send_message(message): # message should be byte type
        self.conn.sendall(message)

    def send_session_key(self):
        self.create_session_key()
        session_key_dic = {'set' : 'session_key', 'value' : self.base64_encode(self.session_key)}
        session_key_json = json.dumps(session_key_dic)
        session_key_json_encrytped_RSA = self.encrypt_RSA(session_key_json, key=self.server_pubkey)
        self.conn.sendall(session_key_json_encrytped_RSA)

    def recieve_session_key(self, session_key_json_encrytped_RSA):
        session_key_json = self.decrypt_RSA(session_key_json_encrytped_RSA, key = self.server_privkey)
        session_key_dic = json.loads(session_key_json)
        return self.base64_decode(session_key_dic['value'])

class server(socket_conn):
    def __init__(self, conn, server_pubkey, server_privkey):
        super().__init__(conn, server_pubkey)
        self.server_privkey = server_privkey




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
