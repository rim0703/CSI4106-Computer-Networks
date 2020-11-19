import socket
import threading
import sys
import time
import os

#create an empty dictionary to store clients(work as client list)
clients={}

#terminate when user enter Ctrl+C
class reqthread(threading.Thread):
   def run(self):
         time.sleep(0)

"""
class client works for:
1. store new clients as an object and store in dictionary "clients"
2. sending and receiving messages via socket
   (client messages/welcome message/client left message)
3. when user left close the socket
4. getId to get the specific client 
"""
class client(object):
    #create new object(client)
    def __init__(self,socket,addr):
        self.addr=addr[0]
        self.port=addr[1]
        self.socket=socket
    #sending messages
    def sendMsg(self,msg,client):
        try:
            if self.port!=client.port :
               self.socket.send((msg).encode('utf8'))
            return True
        except:
            return False
    #sending welcome messages
    def welcomeMsg(self):
        try:
            if len(clients)<2:
               msg="> Connected to the chat server (%s user online)"%(len(clients))
            else:
               msg="> Connected to the chat server (%s users online)"%(len(clients))
            self.socket.send(msg.encode('utf8'))
        except:
            return False
    #receiving messages
    def recv(self):
        try:
            data=self.socket.recv(1024).decode('utf8')
            if not data:
                return False
            return data
        except:
            return False
    #close the socket
    def close(self):
        try:
            self.socket.close()
            return True
        except:
            return False
    #get client object id
    def getId(self):
        return "%s-%s"%(self.addr,self.port)


#get IP and PORT by the command line
HOST=sys.argv[1] #get input by command line
PORT=sys.argv[2] #get input by command line
print("Chat Server started on port "+PORT+".")
#open the socket and create connection by the HOST IP and PORT
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((str(HOST),int(PORT)))

#default: 10 clients can access this server
s.listen(10)


#new client come into the chat room
def new_client(c):
    try:
        #client send message
        while True:
            data=c.recv()
            if not data:
                break
            else:
                print("[%s:%s] %s" % (c.addr,c.port,data))
                data="[%s:%s] %s" % (c.addr,c.port,data)
                broadcast(c,data)
    except Exception:
        print("exception occurr!")
    finally:
        #some client left
        if len(clients)-1<2:
           print("< The user %s:%s left (%s user online)"%(c.addr,c.port,len(clients)-1))
           msg="< The user %s:%s left (%s user online)"%(c.addr,c.port,len(clients)-1)
           broadcast(c,msg)
           
        else:
           print("< The user %s:%s left (%s users online)"%(c.addr,c.port,len(clients)-1))
           msg="< The user %s:%s left (%s users online)"%(c.addr,c.port,len(clients)-1)
           broadcast(c,msg)
        c.close()
        #remove the left client
        clients.pop(c.getId())

#sending messages to all the clients
def broadcast(client,msg):
    for c in clients.values():
        c.sendMsg(msg,client)


try:
    thread=reqthread()
    thread.daemon=True
    thread.start()
    while 1:
          #new client come into the chatting room
          conn, addr=s.accept()
          c=client(conn,addr)
          clients[c.getId()]=c
          if len(clients)<2:
             print ('> New user %s:%s entered (%s user online)' % (c.addr,c.port,len(clients)))
             c.welcomeMsg()
             msg='> New user %s:%s entered (%s user online)' % (c.addr,c.port,len(clients))
             broadcast(c,msg)
          else:
             print ('> New user %s:%s entered (%s users online)' % (c.addr,c.port,len(clients)))
             c.welcomeMsg()
             msg='> New user %s:%s entered (%s users online)' % (c.addr,c.port,len(clients))
             broadcast(c,msg)
          #threading start
          t=threading.Thread(target=new_client,args=(c,))
          t.start()
   
#terminate when enter Ctrl+C
except (KeyboardInterrupt, SystemExit):
     print('')
     print('exit')
     os._exit(1)

#socket close
s.close()   
