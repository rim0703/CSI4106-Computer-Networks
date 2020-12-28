import sys
import socket
import threading
import time

lock=threading.Lock()
#Get the port number by the user input
port=int(sys.argv[1])

#Default total connections
total_connection=20
thread_num=0 #default 0
log_count=0 #count for print the log

#URL filter setting
set_filter_keyword="yonsei"
redirect_dest="http://linuxhowtos.org/"
redirect_server="linuxhowtos.org"

#function status
image_filtering_status="X"
url_filtering_status="X"
#image_type=['image/*']


def run():
    global thread_num
    try:
        #create and set the socket
        con_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        con_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        con_socket.bind(('',port))

        print("Starting proxy server on port",port)
    except Exception as e:
        #catch error
        print("ERROR!")
        print(e)
        sys.exit(1)
    while True:
        try:
            #Connet to the client and get the client's socket and address
            con_socket.listen(total_connection)
            cli_socket,cli_addr=con_socket.accept()
            cli_data=cli_socket.recv(65536)
            if cli_data:
                method=cli_data.splitlines()[0].decode('utf-8').split(' ')[0]
            #Only process the GET method!
            if method=="GET":
                #cli_data=image_filtering(cli_data)
                thread=threading.Thread(target=main_thread,args=(cli_socket,cli_addr,cli_data))
                thread.daemon=True
                thread.start()

                thread_num=thread_num+1

        #If get the Ctrl+C input terminate the proxy server
        except KeyboardInterrupt:
            con_socket.close()
            sys.exit(1)
    con_socket.close()

"""These three functions use to analyze the data from the HTTP"""
def request_call(header):
    for i in range(len(header)):
        if b'HTTP' in header[i]: request=header[i]
        elif b'User-Agent' in header[i]: userAgent=header[i]
        elif b'Accept:' in header[i]:
        	accepts=header[i]
        	acceptsPos=i
    data={
        "request":request.decode('utf-8'),
        "user_agent":userAgent.decode('utf-8')[12:],
        "accepts": accepts.decode('utf-8')[8:],
        "accepts_pos": acceptsPos,
    }
    return data
def response_call(reply):
    for i in range(len(reply)):
        if b'HTTP' in reply[i]: status=reply[i]
        elif b'Content-Type' in reply[i]: con_type=reply[i]
        elif b'Content-Length' in reply[i]: con_length=reply[i]
    data={
        "status":status.decode('utf-8'),
        "con_type":con_type.decode('utf-8')[14:],
        "con_length":con_length.decode('utf-8')[16:],
    }
    return data
def domain_call(header):
    first_line=header[0].split()
    URL_decode=first_line[1].decode('utf-8')
    #jump 7 units to remove the http://(7units)
    server=URL_decode[7:]
    url=URL_decode[7:]
    pos=url.find("/")
    server=server[:pos]
    data={
        "server":server,
        "url":url,
    }
    return data


def main_thread(cli_socket,cli_addr,cli_data):
    global image_filtering_status, url_filtering_status
    global cache_size, cache_dict
    log=[]

    #read requests line by line
    try:
        #analyze data from the HTTP
        data=cli_data.splitlines()
        while data[len(data)-1]=='': data.remove('')
        request=request_call(data)["request"]
        userAgent=request_call(data)["user_agent"]
        accepts=request_call(data)["accepts"]
        acceptsPos=request_call(data)["accepts_pos"]
        server=domain_call(data)["server"]
        url=domain_call(data)["url"]
        port=80

        #check the filter status
        if("?image_off" in url): image_filtering_status="O"
        elif("?image_on" in url): image_filtering_status="X"
        if(server.find(set_filter_keyword)!=-1):url_filtering_status="O"
        else:url_filtering_status="X"
        
        #filtering status log
        log.append(f"[{url_filtering_status}] URL filter | [{image_filtering_status}] Image filter")
        log.append("")
        log.append("[CLI connected to {}:{}]".format(cli_addr[0],cli_addr[1]))
        log.append("[CLI ==> PRX --- SRV]")
        log.append(f"  > {request}")
        log.append(f"  > {userAgent}")

        if(server.find(set_filter_keyword)!=-1):
            server=redirect_dest
            #remove server domain
            line_one=data[0].split()
            line_one[1]=server.encode()
            data[0]=b' '.join(line_one)
            line_two=data[1].split()
            line_two[1]=redirect_server.encode()
            data[1]=b' '.join(line_two)
            
            changed=cli_data.split(b'\r\n')
            changed[0]=data[0]
            changed[1]=data[1]
            #restore the new data 
            cli_data=b'\r\n'.join(changed)
            request=data[0].decode('utf8')
            userAgent=data[5].decode('utf8')

            runServer(redirect_server,port,cli_socket,cli_addr,cli_data,request,userAgent,log)
        else:
            #URL filter OFF
            url_filtering_status="X"
            runServer(server,port,cli_socket,cli_addr,cli_data,request,userAgent,log)
    except Exception as e:
        pass



def runServer(server,port,cli_socket,cli_addr,cli_data,request,userAgent,log):
    global thread_num, log_count
    global cache_size,cache_dict
    try:
        #create server socket
        srv_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        srv_socket.connect((server,port))
        
        log.append(f"[SRV connected to {server}:{port}]")
        srv_socket.sendall(cli_data)#send data to the server
        log.append("[CLI --- PRX ==> SRV]")
        log.append(f"  > {request}")
        log.append(f"  > {userAgent}")

        #Here we set the timeout to check TCP packet loss
        #if it happens we will re-send them
        #ref:https://www.binarytides.com/receive-full-data-with-the-recv-socket-function-in-python/
        srv_socket.setblocking(0)
        all_data=[]
        data=""
        timeout=2
        #beginning time
        begin=time.time()
        while True:
            #if you got some data, then break after timeout
            if all_data and time.time()-begin>timeout:
                break
            #if you got no data at all, wait a little longer, twice the timeout
            elif time.time()-begin > timeout*2:
                break

            #recv something
            try:
                reply=srv_socket.recv(65536)
                #print(reply)
                if reply:
                    all_data.append(reply)
                    begin=time.time()
                else:
                    time.sleep(0.1)
            except Exception as e:
                pass
        
        #join all parts to make final string
        data=b''.join(all_data)

        data_inline=data.splitlines()
        status=response_call(data_inline)["status"]

        con_type=response_call(data_inline)["con_type"]
        #print(con_type)
        con_length=response_call(data_inline)["con_length"]
        log.append("[CLI --- PRX <== SRV]")
        log.append(f'  > {status}')
        log.append(f'  > {con_type} {con_length}bytes')
        
        if image_filtering_status=="O" and 'image' in con_type:
             con_length="0"
             data=data.split(b'\r\n\r\n')[0]
        cli_socket.sendall(data)


        #store the logs
        log.append("[CLI <== PRX --- SRV]")
        log.append(f'  > {status}')
        log.append(f'  > {con_type} {con_length}bytes')
        #close the sockets and print the finishing log
        cli_socket.close()
        log.append("[CLI disconnected]")
        srv_socket.close()
        log.append("[SRV disconnected]")
        thread_num=thread_num-1

        #ALL HAVE DONE!! Just print!
        lock.acquire()
        thread_num_pos=str(threading.currentThread()).find('-')
        thread_num_count=str(threading.currentThread())[thread_num_pos+1]
        log_count=log_count+1
        log.insert(0,f"{log_count} [Conn: {thread_num_count}/{threading.activeCount()}]")
        log.append("---------------------------------------------")
        #print("LOG----")
        for msg in log:
            print(msg)
        lock.release()

    #If get the Ctrl+C input or other errors occur terminate the proxy server
    except Exception as e:
        srv_socket.close()
        cli_socket.close()
        sys.exit(1)

#run our project!
if __name__ == "__main__":
	run()
