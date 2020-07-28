import socket
import _thread

def on_new_client(clientsocket,addr):
    while True:
        msg = clientsocket.recv(1024)
        print (addr, ' >> ', msg)
        msg = input('SERVER >> ')
        clientsocket.send(msg.encode())
    clientsocket.close()

s = socket.socket()
host = '127.0.0.1'
port = 65432

print ('Server started!')
print ('Waiting for clients...')

s.bind((host, port))
s.listen(5)

while True:
   c, addr = s.accept()
   print ('Got connection from', addr)
   _thread.start_new_thread(on_new_client,(c,addr))
s.close()
