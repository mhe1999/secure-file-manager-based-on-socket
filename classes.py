import os
import rsa
import json
import base64
from Crypto.Cipher import AES
import mysql.connector
from mysql.connector import errorcode



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

    def encrypt_file_AES(self, message):
        cipher = AES.new(self.session_key,AES.MODE_EAX)
        nonce = cipher.nonce
        cipherfile, tag = cipher.encrypt_and_digest(message) # encryte data
        return cipherfile, nonce

    def decrypt_file_AES(self, cipherfile, nonce):
        print('decrypting file...')
        cipher = AES.new(self.session_key, AES.MODE_EAX, nonce=nonce)
        message = cipher.decrypt(cipherfile)               # decrype message with session key and nonce
        # message_json = message_json
        return message

    def base64_encode(self, message_bytes):
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        return base64_message

    def base64_decode(self, base64_message):
        base64_bytes = base64_message.encode('ascii')
        message_bytes = base64.b64decode(base64_bytes)
        return message_bytes

#####################################################################################################################################################################
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

    def send_file(self, file_name):
        f = open(file_name, 'rb')
        l = f.read()
        cipherfile, nonce = self.encrypt_file_AES(l)
        cipherfile_base64 = self.base64_encode(cipherfile)
        nonce_base64 = self.base64_encode(nonce)
        message_dic = {'cipherfile' : cipherfile_base64,
                       'nonce' : nonce_base64}
        message_json = json.dumps(message_dic)
        self.conn.sendall(message_json.encode())

    def recieve_file(self, file_name):
        file = open(file_name, 'wb')
        message_json = bytes()
        while True:
            data = self.conn.recv(1024)
            if not data:
                break
            message_json += data
        message_dic = json.loads(message_json)
        cipherfile_base64 = message_dic['cipherfile']
        nonce_base64 = message_dic['nonce']
        cipherfile = self.base64_decode(cipherfile_base64)
        nonce = self.base64_decode(nonce_base64)
        message = self.decrypt_file_AES(cipherfile, nonce)
        file.write(message)

    def send_message(self, message, **kwargs):
        encrypted_message, nonce = self.encrypt_AES(message)
        encrypted_message_base64 = self.base64_encode(encrypted_message)
        nonce_base64 = self.base64_encode(nonce)
        encrypted_message_dic = {'encrypted_message' : encrypted_message_base64 ,
                                  'nonce' : nonce_base64}
        encrypted_message_json = json.dumps(encrypted_message_dic)
        self.conn.sendall(encrypted_message_json.encode())

    def recieve_message(self, encrypted_message_json):
        message_json = json.loads(encrypted_message_json.decode())    # message_json = {'encrypted_message' : aksdlbfvmnsznasfdfb,
        encrypted_message_base64 = message_json['encrypted_message']  #                 'nonce' : mnfmq}
        nonce_base64 = message_json['nonce']
        encrypted_message = self.base64_decode(encrypted_message_base64)
        nonce = self.base64_decode(nonce_base64)
        message = self.decrypt_AES(encrypted_message, nonce) # message = {'type' : login, ...} --- json
        self.recieve_message_handler(message)

    def send_message_handler(self, message):
        message_array = message.split() # FIXME: file names with space
        type = message_array[0]
        if type == 'register':
            self.send_register_command(uname = message_array[1],
                                       password = message_array[2],
                                       conf_label = message_array[3],
                                       integrity_label = message_array[4])

        elif type == 'login':
            self.send_login_command(   uname = message_array[1],
                                       password = message_array[2])

        elif type == 'put':
            self.send_put_command(     filename = message_array[1],
                                       conf_label = message_array[2],
                                       integrity_label = message_array[3])

        elif type == 'read':
            self.send_read_command(    filename = message_array[1])

        elif type == 'write':
            self.send_write_command(   filename = message_array[1],
                                       content = message_array[2])

        elif type == 'get':
            self.send_get_command(    filename = message_array[1])

        else:
            print('not valid input')

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
        file = open(filename, 'rb')
        content = self.base64_encode(file.read())
        dic_message = {'type' : 'put',
                       'filename' : filename,
                       'conf_label' : conf_label,
                       'integrity_label' : integrity_label,
                       'file' : content}
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

##################################################################################################################################################################
class server(socket_conn):
    def __init__(self, conn, server_pubkey, server_privkey):
        super().__init__(conn, server_pubkey)
        self.server_privkey = server_privkey
        self.database_connection()

    def database_connection(self):
        try:
            self.mydb = mysql.connector.connect(
            host="localhost",
            user="Mohammad",
            password="1234",
            database='file_manager'
            )
            self.cursor = self.mydb.cursor()
        except mysql.connector.Error as err:
          if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Something is wrong with your user name or password")
          elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Database does not exist")
          else:
              print('an error')
              print(err)

    def recieve_session_key(self, session_key_json_encrytped_RSA):
        # print('XXXX    ',session_key_json_encrytped_RSA, '\n')
        session_key_json = self.decrypt_RSA(session_key_json_encrytped_RSA, key = self.server_privkey)
        session_key_dic = json.loads(session_key_json)
        self.session_key = self.base64_decode(session_key_dic['value'])

    def recieve_message_handler(self, message_json): # message_json = {'type' : login, ...} ---> json
        message = json.loads(message_json)           # message = {'type' : login, ...} ---> dict
        if message['type'] == 'register':
            self.handle_register_command(message)
        elif message['type'] == 'login':
            self.handle_login_command(message)
        elif message['type'] == 'put':
            self.handle_put_command(message)
        elif message['type'] == 'read':
            self.handle_read_command(message)
        elif message['type'] == 'write':
            self.handle_write_command(message)
        elif message['type'] == 'get':
            self.handle_get_command(message)
        else:
            print('not vaild')

    def handle_register_command(self, message):
        print('in register')
        uname = message['uname']
        salt = self.base64_encode(os.urandom(12))
        password = message['password'] + salt # returns a string of password + salt
        conf_label = int(message['conf_label'])
        integrity_label = int(message['integrity_label'])
        if self.check_uname(uname) and self.check_pass_register(password):
            self.cursor.execute("""INSERT INTO users(uname, pass_hash, salt, conf_label, integ_label, number_of_attempts, last_attempt)
                                            VALUES(%(uname)s , sha2(%(password)s, 256) ,%(salt)s ,%(conf_label)s ,%(integ_label)s ,NULL ,NULL)""",
                                            {'uname' : uname, 'password' : password , 'salt' : salt, 'conf_label' : conf_label , 'integ_label' : integrity_label})
            self.mydb.commit()
        else:
            print('fail')

    def handle_login_command(self, message):
        print('in login')
        uname = message['uname']
        password = message['password']
        if self.check_pass_login(uname, password):
            print('login successfully')
            print(self.user_id)
        else:
            print('unsuccess')

    def handle_put_command(self, message):
        print('in put')
        if self.check_file_name(message['filename'].split('.')[0] + '_server.' + message['filename'].split('.')[1]): # FIXME: file name without .txt
            file = open(message['filename'].split('.')[0] + '_server.' + message['filename'].split('.')[1], 'wb')
            file.write(self.base64_decode(message['file']))
            self.add_file_to_database(message)
        else:
            print('duplicate name of file')

    def handle_read_command(self, message):
        print('in read')

    def handle_write_command(self, message):
        print('in write')

    def handle_get_command(self, message):
        print('in get')

    def check_uname(self, uname):
        self.cursor.execute("SELECT ID FROM users WHERE uname = %(uname)s" , {'uname' : uname})
        user_table = self.cursor.fetchall()
        if not len(user_table):
            return True
        else:
            return False

    def check_pass_register(self, password):
        if len(password) < 8:
            return False
        else:
            return True

    def check_pass_login(self, uname, password):
        # self.cursor.execute("SELECT salt FROM users WHERE uname = %(uname)s" , {'uname' : uname})
        self.cursor.execute(""" SELECT ID
                                FROM users
                                WHERE uname = %(uname)s AND sha2(CONCAT(%(password)s, salt), 256) = pass_hash""" , {'uname' : uname, 'password' : password})

        user_table = self.cursor.fetchall()
        if len(user_table):
            self.user_id = user_table[0][0]
            return True
        else:
            return False

    def check_file_name(self, fname):
        self.cursor.execute(""" SELECT ID
                                FROM files
                                WHERE fname = %(fname)s""" , {'fname' : fname})


        file_table = self.cursor.fetchall()
        if len(file_table):
            return False
        else:
            return True

    def add_file_to_database(self, message):
        fname = message['filename'].split('.')[0] + '_server.' + message['filename'].split('.')[1]
        conf_label = int(message['conf_label'])
        integ_label = int(message['integrity_label'])
        owner_id = 4 # FIXME: owner_id = self.user_id
        self.cursor.execute("""INSERT INTO files(fname, conf_label, integ_label, ownerID)
                                VALUES(%(fname)s , %(conf_label)s ,%(integ_label)s ,%(owner_id)s)""",
                                {'fname' : fname, 'conf_label' : conf_label , 'integ_label' : integ_label, 'owner_id' : owner_id})
        self.mydb.commit()

class clients():
    pass

class files():
    pass



# TODO: calculate session key   CHECK
# TODO: send session key        CHECK
# TODO: recieve session key     CHECK
# TODO: encryption text         CHECK
# TODO: decryption text         CHECK
# TODO: send message            CHECK
# TODO: recieve message         CHECK
# TODO: base64 encode           CHECk
# TODO: base64 decode           CHECK
# TODO: encryption file         CHECK
# TODO: decryption file         CHECK
# TODO: send file               CHECK
# TODO: recieve file            CHECL
# TODO: create database         CHECK
# TODO: calculate hash          CHECK
# TODO: check hash              CHECK
# TODO: hash passwords          CHECK
# TODO: register                CHECK
# TODO: login                   CHECk
# TODO: put
# TODO: read
# TODO: write
# TODO: get
# TODO: BLP
# TODO: Biba
# TODO: weak password
# TODO: backoff
# TODO: logging
# TODO: analyse logs
# TODO: DAC
# TODO: Honeypot
