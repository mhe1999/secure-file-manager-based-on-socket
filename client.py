import socket
import rsa
from classes import socket_conn


server_pubkey = rsa.PublicKey(int('''198710545728042830253499635501841987346
1541179669992532483914203150651172352438303321820385084467843592008121891579
5243744623899403024070535464953327207745707280816151149112673681159838326052
6120182724129912002381565130386206485103768727500904675351361585101139635132
2694293183381935261237401868155491912800800250116691185718942925849159449871
9439799387750137469926299277454098469247496858839507530776827365123736406053
0251116770748039430110821074732249014709370741208212747951559547340860480573
4379799091495243224771586683345998659539518564067592233261543537102023917893
9096433733507311626064586608627154087661325313'''.replace('\n', '')), 65537)

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

# client_crypto = cryptography(server_pubkey = server_pubkey)
# client_socket = socket()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print('hello')
    client_socket = socket_conn(conn = s , server_pubkey = server_pubkey)
    client_socket.send_session_key()
    print(client_socket.base64_encode(client_socket.session_key))
    client_socket.send_register(uname = 'abc',
                                password = 'def',
                                conf_label = '1',
                                integrity_label = '2')