import os
import rsa
import json
import base64
import re
from Cryptodome.Cipher import AES
import mysql.connector
from mysql.connector import errorcode
import passwordmeter
import datetime


class cryptography():
    def __init__(self, server_pubkey):
        self.server_pubkey = server_pubkey

    # message : string, key : rsa.PublicKey default = server_pubkey
    def encrypt_RSA(self, message, key):
        # returns a 'byte' type of encrypted message
        return rsa.encrypt(message.encode(), self.server_pubkey)

    # encrypted_message : 'byte' type, key : rsa.PrivateKey
    def decrypt_RSA(self, encrypted_message, key):
        # returns a string of decrypted message
        return rsa.decrypt(encrypted_message, key).decode()

    def create_session_key(self):
        self.session_key = os.urandom(32)
        return self.session_key   # returns a 256 bit 'byte' type

    def encrypt_AES(self, plaintext):
        cipher = AES.new(self.session_key, AES.MODE_EAX)  # FIXME: EAD mode
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(
            plaintext.encode())  # encryte data
        return ciphertext, nonce

    def decrypt_AES(self, message_bytes, nonce):
        print('decrypting data...')
        cipher = AES.new(self.session_key, AES.MODE_EAX,
                         nonce=nonce)  # FIXME: EAD mode
        # decrype message with session key and nonce
        plaintext = cipher.decrypt(message_bytes)
        plaintext = plaintext.decode()
        return plaintext

    # def encrypt_file_AES(self, message):
    #     cipher = AES.new(self.session_key,AES.MODE_EAX)# FIXME: EAD mode
    #     nonce = cipher.nonce
    #     cipherfile, tag = cipher.encrypt_and_digest(message) # encryte data
    #     return cipherfile, nonce
    #
    # def decrypt_file_AES(self, cipherfile, nonce):
    #     print('decrypting file...')
    #     cipher = AES.new(self.session_key, AES.MODE_EAX, nonce=nonce)# FIXME: EAD mode
    #     message = cipher.decrypt(cipherfile)               # decrype message with session key and nonce
    #     # message_json = message_json
    #     return message

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
        super().__init__(server_pubkey=server_pubkey)
        self.conn = conn
    def send_session_key(self):
        self.create_session_key()
        session_key_dic = {'type': 'session_key',
                           'value': self.base64_encode(self.session_key)}
        session_key_json = json.dumps(session_key_dic)
        session_key_json_encrytped_RSA = self.encrypt_RSA(
            session_key_json, key=self.server_pubkey)
        # print('XXXX    ',session_key_json_encrytped_RSA, '\n')
        print(self.base64_encode(session_key_json_encrytped_RSA), '\n\n')
        self.conn.sendall(session_key_json_encrytped_RSA)

    # def send_file(self, file_name):
    #     f = open(file_name, 'rb')
    #     l = f.read()
    #     cipherfile, nonce = self.encrypt_file_AES(l)
    #     cipherfile_base64 = self.base64_encode(cipherfile)
    #     nonce_base64 = self.base64_encode(nonce)
    #     message_dic = {'cipherfile' : cipherfile_base64,
    #                    'nonce' : nonce_base64}
    #     message_json = json.dumps(message_dic)
    #     self.conn.sendall(message_json.encode())
    #
    # def recieve_file(self, file_name):
    #     file = open(file_name, 'wb')
    #     message_json = bytes()
    #     while True:
    #         data = self.conn.recv(1024)
    #         if not data:
    #             break
    #         message_json += data
    #     message_dic = json.loads(message_json)
    #     cipherfile_base64 = message_dic['cipherfile']
    #     nonce_base64 = message_dic['nonce']
    #     cipherfile = self.base64_decode(cipherfile_base64)
    #     nonce = self.base64_decode(nonce_base64)
    #     message = self.decrypt_file_AES(cipherfile, nonce)
    #     file.write(message)

    def send_message(self, message, **kwargs):
        encrypted_message, nonce = self.encrypt_AES(message)
        encrypted_message_base64 = self.base64_encode(encrypted_message)
        nonce_base64 = self.base64_encode(nonce)
        encrypted_message_dic = {'encrypted_message': encrypted_message_base64,
                                 'nonce': nonce_base64}
        encrypted_message_json = json.dumps(encrypted_message_dic)
        self.conn.sendall(encrypted_message_json.encode())

    def recieve_message(self, encrypted_message_json):
        # message_json = {'encrypted_message' : aksdlbfvmnsznasfdfb,
        message_json = json.loads(encrypted_message_json.decode())
        # 'nonce' : mnfmq}
        encrypted_message_base64 = message_json['encrypted_message']
        nonce_base64 = message_json['nonce']
        encrypted_message = self.base64_decode(encrypted_message_base64)
        nonce = self.base64_decode(nonce_base64)
        # message = {'type' : login, ...} --- json
        message = self.decrypt_AES(encrypted_message, nonce)
        self.recieve_message_handler(message)

    # message_json = {'type' : login, ...} ---> json
    def recieve_message_handler(self, message_json):
        # message = {'type' : login, ...} ---> dict
        message = json.loads(message_json)
        if message['type'] == 'register':
            # FIXME: user input is name of BLP and BIBA levels, not number
            self.handle_register_command(message)
        elif message['type'] == 'register_answer':
            self.handle_register_answer_command(message)
        elif message['type'] == 'login':
            self.handle_login_command(message)
        elif message['type'] == 'login_answer':
            self.handle_login_answer_command(message)
        elif message['type'] == 'put':
            # FIXME: user input is name of BLP and BIBA levels, not number
            self.handle_put_command(message)
        elif message['type'] == 'put_answer':
            self.handle_put_answer_command(message)
        elif message['type'] == 'read':
            self.handle_read_command(message)
        elif message['type'] == 'read_answer':
            self.handle_read_answer_command(message)
        elif message['type'] == 'write':
            self.handle_write_command(message)
        elif message['type'] == 'write_answer':
            self.handle_write_answer_command(message)
        elif message['type'] == 'get':
            self.handle_get_command(message)
        elif message['type'] == 'get_answer':
            self.handle_get_answer_command(message)
        elif message['type'] == 'ls':
            self.handle_ls_command(message)
        elif message['type'] == 'ls_answer':
            self.handle_ls_answer_command(message)
        else:
            print('not vaild')

    def send_message_handler(self, message):
        message_array = message.split()  # FIXME: file names with space

        type = message_array[0]
        if type == 'register':
            if len(message_array) == 5:
                self.send_register_command(status='correct',
                                        uname=message_array[1],
                                        password=message_array[2],
                                        conf_label=message_array[3],
                                        integrity_label=message_array[4])
            else:
                self.send_register_command(status='wrong', 
                                           uname='',
                                           password='',
                                           conf_label='',
                                           integrity_label='')

        elif type == 'login':
            if len(message_array) == 3:
                self.send_login_command(uname=message_array[1],
                                        password=message_array[2],status = 'correct')
            else:
                self.send_login_command(uname='',
                                        password='', status='wrong')

      
        elif type == 'put':
            self.send_put_command(filename=message_array[1],
                                  conf_label=message_array[2],
                                  integrity_label=message_array[3])

        # FIXME: for impelement DAC

      
        elif type == 'read':
            if len(message_array) == 2:
                self.send_read_command(
                    filename=message_array[1], status='correct')
            else:
                self.send_read_command(filename='',status='wrong')
      
        elif type == 'write':
            if len(message_array) == 3:
                self.send_write_command(filename=message_array[1],
                                        content=message_array[2],
                                        status='correct')
            else:
                self.send_write_command(filename='',
                                        content='',
                                        status='wrong')
        elif type == 'get':
            if len(message_array) == 2:
                self.send_get_command(filename=message_array[1], status='correct')
            else:
                self.send_get_command(filename='', status='wrong')

        elif type == 'ls':
            if len(message_array) == 1:
                self.send_ls_command(status='correct')
            else:
                self.send_ls_command(status='wrong')

        else:
            print('not valid input')

    def send_register_command(self, uname, password, conf_label, integrity_label, status):
        dic_message = {'type': 'register',
                    'uname': uname,
                    'password': password,
                    'conf_label': conf_label,
                    'integrity_label': integrity_label,
                    'status': status}

        json_message = json.dumps(dic_message)
        self.send_message(json_message)

    def send_login_command(self, uname, password, status):
        dic_message = {'type': 'login',
                       'uname': uname,
                       'password': password
                       ,'status': status}
        json_message = json.dumps(dic_message)
        self.send_message(json_message)

    def send_put_command(self, filename, conf_label, integrity_label):
        file = open(filename, 'rb')
        content = self.base64_encode(file.read())
        dic_message = {'type': 'put',
                       'filename': filename,
                       'conf_label': conf_label,
                       'integrity_label': integrity_label,
                       'file': content}
        json_message = json.dumps(dic_message)
        self.send_message(json_message)

    def send_read_command(self, filename, status):
        dic_message = {'type': 'read',
                       'filename': filename,
                       'status': status}
        json_message = json.dumps(dic_message)
        self.send_message(json_message)

    def send_write_command(self, filename, content, status):
        dic_message = {'type': 'write',
                       'filename': filename,
                       'content': content,
                       'status': status}
        json_message = json.dumps(dic_message)
        self.send_message(json_message)

    def send_get_command(self, filename, status):
        dic_message = {'type': 'get',
                       'filename': filename,
                       'status': status}
        json_message = json.dumps(dic_message)
        self.send_message(json_message)

    def send_ls_command(self, status):
        dic_message = {'type': 'ls',
                        'status': status}
        json_message = json.dumps(dic_message)
        self.send_message(json_message)

##################################################################################################################################################################


class server(socket_conn):
    def __init__(self, conn, server_pubkey, server_privkey, ClientAddress):
        super().__init__(conn, server_pubkey)
        self.server_privkey = server_privkey
        self.database_connection()
        self.ClientAddress = ClientAddress
        self.LoggedUsername = ''
        self.LoggedFlag = False
        print(self.ClientAddress)
    
    def login_log(self,uname,status, addr):

        f = open("filemanager.log", "a")
        current_time = datetime.datetime.now()
        msg = 'Login: ' + status + ', username: ' + uname +  ', IP address: ' +  str(addr[0]) + ', Port Number: ' + str(addr[1]) +', @time: ' + str(current_time) + '\n'
        f.write(msg)
        f.close()



    def register_log(self,uname,status,addr):
        f = open("filemanager.log", "a")
        current_time = datetime.datetime.now()
        msg = 'Register: ' + status + ', username: ' + uname +  ', IP address: ' +  str(addr[0]) + ', Port Number: ' + str(addr[1]) +', @time: ' + str(current_time) + '\n'
        f.write(msg)
        f.close()


    def ls_log(self, uname, addr):
        f = open("filemanager.log", "a")
        current_time = datetime.datetime.now()
        msg = 'ls: ' + ' username: ' + uname +  ', IP address: ' +  str(addr[0]) + ', Port Number: ' + str(addr[1]) +', @time: ' + str(current_time) + '\n'
        f.write(msg)
        f.close()

    def get_log(self, status, filename, uname, addr):
        f = open("filemanager.log", "a")
        current_time = datetime.datetime.now()
        msg = 'Get: ' + status + ', Filename: '+ filename + ', username: ' + uname + ', IP address: ' + \
            str(addr[0]) + ', Port Number: ' + str(addr[1]) + \
            ', @time: ' + str(current_time) + '\n'
        f.write(msg)
        f.close()

    def loginChecker_log(self, type, uname, addr):
        f = open("filemanager.log", "a")
        current_time = datetime.datetime.now()
        if uname == '':
            msg = 'Access: ' + type + ', IP address: ' + \
                str(addr[0]) + ', Port Number: ' + str(addr[1]) + \
                ', @time: ' + str(current_time) + '\n'

        else:
            msg = 'Access: ' + type + ', username: ' + uname + ', IP address: ' + \
                str(addr[0]) + ', Port Number: ' + str(addr[1]) + \
                ', @time: ' + str(current_time) + '\n'
        
        f.write(msg)
        f.close()

    def invalidCommand_log(self, type, uname, addr):

        f = open("filemanager.log", "a")
        current_time = datetime.datetime.now()
        if uname == '':
            msg = 'commandParameters: ' + type + ', IP address: ' + \
                str(addr[0]) + ', Port Number: ' + str(addr[1]) + \
                ', @time: ' + str(current_time) + '\n'

        else:
            msg = 'commandParameters: ' + type + ', username: ' + uname + ', IP address: ' + \
                str(addr[0]) + ', Port Number: ' + str(addr[1]) + \
                ', @time: ' + str(current_time) + '\n'

        f.write(msg)
        f.close()









    def database_connection(self):
        try:
            self.mydb = mysql.connector.connect(
                host="localhost",
                user="root",
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
        session_key_json = self.decrypt_RSA(
            session_key_json_encrytped_RSA, key=self.server_privkey)
        session_key_dic = json.loads(session_key_json)
        self.session_key = self.base64_decode(session_key_dic['value'])

    def handle_register_command(self, message):
        if self.LoggedFlag == False:
            if message['status'] == 'correct':
                print('in register')
                uname = message['uname']
                salt = self.base64_encode(os.urandom(12))
                # returns a string of password + salt
                password = message['password'] + salt
                conf_label = int(message['conf_label'])
                integrity_label = int(message['integrity_label'])
                if self.check_uname(uname) and self.check_pass_register(uname, message['password']):
                    self.cursor.execute("""INSERT INTO users(uname, pass_hash, salt, conf_label, integ_label, number_of_attempts, block_time, is_block)
                                                    VALUES(%(uname)s , sha2(%(password)s, 256) ,%(salt)s ,%(conf_label)s ,%(integ_label)s ,0 ,NULL, 0)""",
                                        {'uname': uname, 'password': password, 'salt': salt, 'conf_label': conf_label, 'integ_label': integrity_label})
                    self.mydb.commit()
                    answer_dic = {'type': 'register_answer',
                                'content': 'register successfully'}
                    self.register_log(uname, 'Successful Register', self.ClientAddress)

                elif not self.check_uname(uname):
                    print('duplicate user name')
                    answer_dic = {'type': 'register_answer',
                                'content': 'ERROR : duplicate user name'}
                    self.register_log(uname, 'Unsuccessful Register duplicate username', self.ClientAddress)

                else:
                    print('weak password')
                    answer_dic = {'type': 'register_answer',
                                'content': 'ERROR : weak password'}
                    self.register_log(uname, 'Unsuccessful Register weak password', self.ClientAddress)
                answer_json = json.dumps(answer_dic)
                self.send_message(answer_json)

            else:
                print('wrong parameters')
                answer_dic = {'type': 'register_answer',
                              'content': 'ERROR : invalid input, sample command: register <username> <password> <conf.label> <integrity label>'}
                self.invalidCommand_log('register', self.LoggedUsername, self.ClientAddress)
                answer_json = json.dumps(answer_dic)
                self.send_message(answer_json)



        else:
            print('first must logout')
            answer_dic = {'type': 'register_answer',
                          'content': 'ERROR : You must log out before you can register'}
            answer_json = json.dumps(answer_dic)
            self.loginChecker_log('register', self.LoggedUsername, self.ClientAddress)
            self.send_message(answer_json)



    def handle_login_command(self, message):
        print('in login')

        if message['status'] == 'correct':
            uname = message['uname']
            self.LoggedUsername = uname  
            password = message['password']

    #       temp =  self.check_possible_backoff(uname)
            if (not self.check_uname(uname)) and (self.check_pass_login(uname, password)):
                print('login successfully')
                print(self.user_id)
                print(self.user_conf)
                print(self.user_integ)

                answer_dic = {'type': 'login_answer',
                            'content': 'Login successfully'}
                self.LoggedFlag = True
                self.login_log(uname, 'Login successfully', self.ClientAddress)

            elif (self.check_uname(uname)) or (not self.check_pass_login(uname, password)):
                answer_dic = {'type': 'login_answer',
                            'content': 'ERROR : invalid username or password'}
                print('invalid username or password')
                if (self.check_uname(uname)):
                    self.login_log(uname, 'Invalid username', self.ClientAddress)
                else:
                    self.login_log(uname, 'Invalid password', self.ClientAddress)
    #        elif not temp == 'True':
    #           answer_dic = {'type': 'login_answer', 'content': temp}
    #          print('wait', temp, 'to try again')

    #        elif not self.check_pass_login(uname, password):
    #            answer_dic = {'type': 'login_answer',
    #                          'content': 'ERROR : invalid password'}
    #           print('invalid password')
    #          self.update_login_backoff(uname)

            answer_json = json.dumps(answer_dic)
            self.send_message(answer_json)

        else:
            answer_dic = {'type': 'login_answer',
                          'content': 'ERROR: invalid input, sample command: login <username> <password>'}

            self.invalidCommand_log(
                'login', self.LoggedUsername, self.ClientAddress)
            answer_json = json.dumps(answer_dic)
            self.send_message(answer_json)


    def handle_put_command(self, message):
        print('in put')
        # FIXME: file name without .txt
        if self.check_file_name(message['filename'].split('.')[0] + '_server.' + message['filename'].split('.')[1]):
            file = open(message['filename'].split('.')[
                        0] + '_server.' + message['filename'].split('.')[1], 'wb')  # FIXME: file name without .txt
            file.write(self.base64_decode(message['file']))
            self.add_file_to_database(message)
            answer_dic = {'type': 'put_answer',
                          'content': 'File put in server successfully'}
        else:
            print('duplicate name of file')
            answer_dic = {'type': 'put_answer',
                          'content': 'ERROR : Duplicate name'}

        answer_json = json.dumps(answer_dic)
        self.send_message(answer_json)

    def handle_read_command(self, message):
        if self.LoggedFlag == True:
            if message['status'] == 'correct':
                if not self.check_file_name(message['filename']) and self.check_BLP_read(message['filename']) and self.check_BIBA_read(message['filename']):
                    file = open(message['filename'], 'rb')
                    content = file.read()
                    content_base64 = self.base64_encode(content)
                    content_dic = {'type': 'read_answer', 'content': content_base64}
                    print('read successfully, sending data to client')
                elif self.check_file_name(message['filename']):
                    print('no such file')
                    content_dic = {'type': 'read_answer',
                                'content': 'ERROR : no such file'}
                elif not self.check_BLP_read(message['filename']):
                    print('not BLP authorize')
                    content_dic = {'type': 'read_answer',
                                'content': 'ERROR : not BLP authorize'}
                elif not self.check_BIBA_read(message['filename']):
                    print('not BIBA authorize')
                    content_dic = {'type': 'read_answer',
                                'content': 'ERROR : not BIBA authorize'}
            else:
                content_dic = {'type': 'read_answer',
                               'content': 'ERROR: invalid input, sample command: read <filename>'}
                                
        else:
            content_dic = {'type': 'read_answer',
                           'content': 'ERROR: must be logged in'}
            self.loginChecker_log(
                'read', self.LoggedUsername, self.ClientAddress)


        content_json = json.dumps(content_dic)
        self.send_message(content_json)


    def handle_write_command(self, message):  # FIXME: messages with spaces
        print('in write')
        if not self.check_file_name(message['filename']) and self.check_BLP_write(message['filename']) and self.check_BIBA_write(message['filename']):
            file = open(message['filename'], 'wt')
            file.write(message['content'])
            print('write successfully')
            content_dic = {'type': 'write_answer',
                           'content': 'writing in file done successfully'}
        elif self.check_file_name(message['filename']):
            print('no such file')
            content_dic = {'type': 'write_answer',
                           'content': 'ERROR : no such file'}
        elif not self.check_BIBA_write(message['filename']):
            print('no such file')
            content_dic = {'type': 'write_answer',
                           'content': 'ERROR : not BIBA authorize'}
        elif self.check_BLP_write(message['filename']):
            print('no such file')
            content_dic = {'type': 'write_answer',
                           'content': 'ERROR : not BLP authorize'}

        content_json = json.dumps(content_dic)
        self.send_message(content_json)

    def handle_get_command(self, message):
        
        if self.LoggedFlag == True:                
            print('in get')
            if message['status'] == 'correct':
                if not self.check_file_name(message['filename']):
                    #FIXME: check if file not exist
                    file = open(message['filename'], 'rb')
                    content = file.read()
                    content_base64 = self.base64_encode(content)
                    content_dic = {'type': 'get_answer',
                                'content': content_base64, 'filename': message['filename']}
                    print('read successfully, sending data to client')
                    self.get_log('read successfully, sending data to client',
                                message['filename'], self.LoggedUsername, self.ClientAddress)

                    
                    # FIXME: delete file
                    #FIXME : dont check who is owner

                else:
                    content_dic = {'type': 'get_answer',
                                'content': 'ERROR : no such file'}
                    self.get_log('no such file',
                                message['filename'], self.LoggedUsername, self.ClientAddress)
                    

            else:
                content_dic = {'type': 'get_answer',
                               'content': 'ERROR: invalid input, sample command: get <filename>'}
                self.invalidCommand_log(
                    'get', self.LoggedUsername, self.ClientAddress)


        else:
            print('must be logged in')
            content_dic = {'type': 'get_answer',
                           'content': 'ERROR: must be logged in'}
            self.loginChecker_log(
                'get', self.LoggedUsername, self.ClientAddress)
        content_json = json.dumps(content_dic)
        self.send_message(content_json)

    
    def handle_ls_command(self,message):
        if self.LoggedFlag == True:                
            if message['status'] == 'correct':
                print('in ls...')
                self.cursor.execute("""SELECT f.fname , u.uname, conf.conf_name, integrity.integ_name
                                    FROM users as u inner join files as f on(u.ID = f.ownerID)
                                    inner join conf on(f.conf_label = conf.ID)
                                    inner join integrity on (f.integ_label = integrity.ID)""")
                content_dic = {'type': 'ls_answer', 'content': self.cursor.fetchall()}
                content_json = json.dumps(content_dic)
                self.ls_log(self.LoggedUsername, self.ClientAddress)
                self.send_message(content_json)

            else:
                answer_dic = {'type': 'ls_answer',
                            'content': 'ERROR: invalid input, sample command: ls'}

                self.invalidCommand_log(
                    'ls', self.LoggedUsername, self.ClientAddress)
                answer_json = json.dumps(answer_dic)
                self.send_message(answer_json)


        else:
            print('must be logged in for ls command')
            content_dic = {'type': 'ls_answer', 'content': 'ERROR: must be logged in'}
            self.loginChecker_log('ls', self.LoggedUsername, self.ClientAddress)
            content_json = json.dumps(content_dic)
            self.send_message(content_json)


    def check_uname(self, uname):
        self.cursor.execute(
            "SELECT ID FROM users WHERE uname = %(uname)s", {'uname': uname})
        user_table = self.cursor.fetchall()
        if not len(user_table):
            return True
        else:
            return False

    def check_pass_register(self, uname, password):
        strength, improvements = passwordmeter.test(password)
        if (strength < 0.85) or ('length' in improvements) or ('charmix' in improvements) or ('casemix' in improvements) or ('notword' in improvements) or ('variety' in improvements) or (uname in password):
            return False
        else:
            return True

    def check_pass_login(self, uname, password):
        # self.cursor.execute("SELECT salt FROM users WHERE uname = %(uname)s" , {'uname' : uname})
        self.cursor.execute(""" SELECT ID, conf_label, integ_label
                                FROM users
                                WHERE uname = %(uname)s AND sha2(CONCAT(%(password)s, salt), 256) = pass_hash""", {'uname': uname, 'password': password})

        user_table = self.cursor.fetchall()
        if len(user_table):
            self.user_id = user_table[0][0]
            self.user_conf = user_table[0][1]
            self.user_integ = user_table[0][2]
            return True
        else:
            return False

    def check_file_name(self, fname):
        self.cursor.execute(""" SELECT ID
                                FROM files
                                WHERE fname = %(fname)s""", {'fname': fname})

        file_table = self.cursor.fetchall()
        if len(file_table):
            return False
        else:
            return True

    def add_file_to_database(self, message):
        fname = message['filename'].split(
            '.')[0] + '_server.' + message['filename'].split('.')[1]  # FIXME: file name without .txt
        conf_label = int(message['conf_label'])
        integ_label = int(message['integrity_label'])
        owner_id = self.user_id  # FIXME: owner_id = self.user_id
        self.cursor.execute("""INSERT INTO files(fname, conf_label, integ_label, ownerID)
                                VALUES(%(fname)s , %(conf_label)s ,%(integ_label)s ,%(owner_id)s)""",
                            {'fname': fname, 'conf_label': conf_label, 'integ_label': integ_label, 'owner_id': owner_id})
        self.mydb.commit()

    def check_BLP_read(self, filename):
        self.cursor.execute(""" SELECT conf_label
                                FROM files
                                WHERE fname = %(fname)s""", {'fname': filename})

        file_table = self.cursor.fetchall()
        if file_table[0][0] <= self.user_conf:
            return True
        else:
            return False

    def check_BLP_write(self, filename):
        self.cursor.execute(""" SELECT conf_label
                                FROM files
                                WHERE fname = %(fname)s""", {'fname': filename})

        file_table = self.cursor.fetchall()
        if file_table[0][0] >= self.user_integ:
            return True
        else:
            return False

    def check_BIBA_read(self, filename):
        self.cursor.execute(""" SELECT integ_label
                                FROM files
                                WHERE fname = %(fname)s""", {'fname': filename})

        file_table = self.cursor.fetchall()
        if file_table[0][0] >= self.user_integ:
            return True
        else:
            return False

    def check_BIBA_write(self, filename):
        self.cursor.execute(""" SELECT integ_label
                                FROM files
                                WHERE fname = %(fname)s""", {'fname': filename})

        file_table = self.cursor.fetchall()
        if file_table[0][0] <= self.user_integ:
            return True
        else:
            return False

    def update_login_backoff(self, uname):
        self.cursor.execute("""UPDATE users
                               SET users.number_of_attempts = users.number_of_attempts + 1
                               WHERE users.uname = %(uname)s""", {'uname': uname})
        self.mydb.commit()

        self.cursor.execute("""SELECT users.number_of_attempts
                               FROM users
                               WHERE users.uname = %(uname)s""", {'uname': uname})

        content = self.cursor.fetchall()
        if content[0][0] >= 5:
            self.block_user(uname)

    def block_user(self, uname):
        self.cursor.execute("""UPDATE users
                               SET users.is_block = 1 , users.block_time = NOW()
                               WHERE users.uname = %(uname)s""", {'uname': uname})
        self.mydb.commit()

    def unblock_user(self, uname):
        self.cursor.execute("""UPDATE users
                               SET users.is_block = 0 , users.block_time = NULL , users.number_of_attempts = 0
                               WHERE users.uname = %(uname)s""", {'uname': uname})
        self.mydb.commit()

    def check_possible_backoff(self, uname):
        self.cursor.execute("""SELECT CASE
		                          WHEN h.is_block = 1 AND TIMEDIFF(NOW(), h.block_time) < cast('00:05:00' as time) THEN TIMEDIFF('00:05:00', TIMEDIFF(NOW(), h.block_time))
                                  WHEN h.is_block = 1 AND TIMEDIFF(NOW(), h.block_time) >= cast('00:05:00' as time) THEN 'unblock'
                                  when h.is_block = 0 THEN 'not block'
                                  END
                                FROM users as h
                                WHERE uname = %(uname)s""", {'uname': uname})
        resault = self.cursor.fetchall()
        print(resault[0][0])
        if resault[0][0] == 'unblock':
            self.unblock_user(uname)
            return 'True'
        elif resault[0][0] == 'not block':
            return 'True'
        else:
            return resault[0][0]


class clients(socket_conn):
    def __init__(self, conn, server_pubkey):
        super().__init__(conn, server_pubkey)

    def handle_read_answer_command(self, message):
        print('in read answer...')
        if 'ERROR' in message['content']:
            print(message['content'])
        else:
            print(self.base64_decode(message['content']).decode())

    def handle_ls_answer_command(self, message):
        if 'ERROR' in message['content']:
            print(message['content'])
        else:                
            print('file name'.ljust(20), '|', 'owner name'.ljust(10), '|',
                'confidentiality'.ljust(15), '|', 'integiry'.ljust(20))
            print('-'*68)
            for row in message['content']:
                print(row[0].ljust(20), '|', row[1].ljust(10),
                    '|', row[2].ljust(15), '|', row[3].ljust(20))

    def handle_register_answer_command(self, message):
        print(message['content'])

    def handle_login_answer_command(self, message):
        print(message['content'])

    def handle_put_answer_command(self, message):
        print(message['content'])

    def handle_write_answer_command(self, message):
        print(message['content'])

    def handle_get_answer_command(self, message):
        # file.write(self.base64_decode(message['content']))
        # self.add_file_to_database(message)
        if 'ERROR' in message['content']:
            print(message['content'])
        else:
            file = open('1' + message['filename'], 'wb')
            file.write(self.base64_decode(message['content']))


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
# TODO: put                     CHECK
# TODO: read                    CHECK
# TODO: ls                      CHECK
# TODO: write                   CHECK
# TODO: get                     CHECK
# TODO: BLP                     CHECK
# TODO: Biba                    CHECK
# TODO: weak password           CHECK
# TODO: backoff
# TODO: logging
# TODO: analyse logs
# TODO: DAC
# TODO: Honeypot
