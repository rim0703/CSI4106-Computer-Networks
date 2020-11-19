import socket
import threading
import sys
import time
import os

#terminate when user enter Ctrl+C
class reqthread(threading.Thread):
   def run(self):
         time.sleep(0)

#get IP and PORT by the command line
HOST=str(sys.argv[1])
PORT=int(sys.argv[2])
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#connect to the server
s.connect((HOST,PORT))


#sending messages to server, then server->other clients
def SendMsg(s):
        time.sleep(0.5)
        try:
           thread=reqthread()
           thread.daemon=True
           thread.start()
           while True:
               sendMsg=input()
               #clear the input and show the input in new format
               sys.stdout.write("\033[F")
               print("[You]"+sendMsg)
               s.send(sendMsg.encode('utf8'))
        except (KeyboardInterrupt, SystemExit):
            print('')
            print('exit')
            os._exit(1)
            s.close()
#receiving messages from server (server message/other client's message)
def ReceiveMsg(s,thout):
    thout.start()
    while True:
        try:
            receiveMsg = s.recv(1024).decode('utf8')
            if not receiveMsg:
                break
            print(receiveMsg)
        except:
             break

try:
   thread=reqthread()
   thread.daemon=True
   thread.start()
   #threading for sending & threading for receiving
   thout=threading.Thread(target=SendMsg, args=(s,))
   thin=threading.Thread(target=ReceiveMsg,args=(s,thout))
   thin.start()
   thin.join()
   thout.join()
except(KeyboardInterrupt, SystemExit):
   print('')
   print('exit')
   os._exit(1)
#close the socket
s.close()
     
