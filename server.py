import socket
import _thread
import rsa
from classes import server

server_pubkey = rsa.PublicKey(int('''198710545728042830253499635501841987346
1541179669992532483914203150651172352438303321820385084467843592008121891579
5243744623899403024070535464953327207745707280816151149112673681159838326052
6120182724129912002381565130386206485103768727500904675351361585101139635132
2694293183381935261237401868155491912800800250116691185718942925849159449871
9439799387750137469926299277454098469247496858839507530776827365123736406053
0251116770748039430110821074732249014709370741208212747951559547340860480573
4379799091495243224771586683345998659539518564067592233261543537102023917893
9096433733507311626064586608627154087661325313'''.replace('\n', '')), 65537)

server_privkey = rsa.PrivateKey(int('''1987105457280428302534996355018419873
4615411796699925324839142031506511723524383033218203850844678435920081218915
7952437446238994030240705354649533272077457072808161511491126736811598383260
5261201827241299120023815651303862064851037687275009046753513615851011396351
3226942931833819352612374018681554919128008002501166911857189429258491594498
7194397993877501374699262992774540984692474968588395075307768273651237364060
5302511167707480394301108210747322490147093707412082127479515595473408604805
7343797990914952432247715866833459986595395185640675922332615435371020239178
939096433733507311626064586608627154087661325313'''.replace('\n','')), 65537
,int('''74957994895840133810321161921914912357471689341595671739730727574180
0788606389974132505967011889681085213311402774448045920002503992494425710308
0338667163424865287347432875528613540954317357716622911189007254715469205415
8838468723551131136264482415068756685084365468971189276408087345359576566352
9539819310354108163894608752944219139226219575208927280232187693038391594309
5263386256634614569063232806778092835147039518402741356333271968021962477932
1089464401524329799200768127174803037575818067928350152049048084243032101164
7609350999063274207313475630191562697582493917187806068786484921925237389122
1140095664017281'''.replace('\n', '')), int('''21659630307499110584526319260
8952329988635327677935924383591238641020101852941320589037887355493382250226
4425081479600258263089774445317483636496920501061180145137619292510002398336
5332694529510059553458106009614528640071676879428593622444913338231690653268
98889436935333334802409677204366469098956516562077466352927879748264377'''.replace('\n','')),
int(''' 91742353358286186879954211373295269340311584242374929055287051742022
0736763091873097644996850939292048249256703492364894297992748025257126924381
9509884481494194910689757882715889152269263940976025398257968300594440519841
640583295586382361005225512629383144758989360820455721364042654072969'''.replace('\n','')))

def on_new_client(clientsocket):
    server_socket = server(conn = clientsocket,
                           server_pubkey = server_pubkey,
                           server_privkey = server_privkey)
    while True:
        msg = clientsocket.recv(1024)
        d = server_socket.recieve_session_key(msg)
        print(server_socket.base64_encode(d))
        break
    clientsocket.close()

s = socket.socket()
host = '127.0.0.1'
port = 65432

print ('Server started!')
print ('Waiting for clients...')

s.bind((host, port))
s.listen(5)

while True:
    print('hey')
    c, addr = s.accept()
    print ('Got connection from', addr)
    _thread.start_new_thread(on_new_client,(c,))
    input()
    break
s.close()
