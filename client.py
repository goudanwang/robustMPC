# import socket
#
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# # 建立连接:
# s.connect(('127.0.0.1', 9999))
# # 接收欢迎消息:
# print(s.recv(1024).decode('utf-8'))
# for data in [b'Michael', b'Tracy', b'Sarah']:
#     # 发送数据:
#     s.send(data)
#     print(s.recv(1024).decode('utf-8'))
# s.send(b'exit')
# s.close()

import argparse
import socket
from multiprocessing import Process
import threading
import time

port = [60980, 60981, 60982, 60983, 60984]

def tcplink(sock, addr, port):
      print('Accept new connection from %s:%s...' % addr)
      sock.send(b'Welcome!')
      while True:
            data = sock.recv(1024)
            time.sleep(1)
            if not data or data.decode('utf-8') == 'exit':
                  break
            sock.send(('Port:%d Hello, %s!' % (port, data.decode('utf-8'))).encode('utf-8'))
      sock.close()
      print('Connection from %s:%s closed.' % addr)

def link(s, index):
    while True:
        # 接受一个新连接:
        sock, addr = s.accept()
        # 创建新线程来处理TCP连接:
        t = threading.Thread(target=tcplink, args=(sock, addr, port[index]))
        t.start()

def conn(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 建立连接:
    time.sleep(10)
    s.connect(('127.0.0.1', p))
    # 接收欢迎消息:
    print(s.recv(1024).decode('utf-8'))
    for data in [b'hahaha', b'eeeee', b'kgkgkgkg']:
        # 发送数据:
        s.send(data)
        print(s.recv(1024).decode('utf-8'))
    s.send(b'exit')
    s.close()

if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--id', type=int, required=True,
                        help='which one')

    args = parser.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', port[args.id]))
    s.listen(5)
    print('Waiting for connection...', args.id)

    pro = []

    for i in range(5):
        if (i == args.id):
            p = Process(target=link, args=(s, i))
        else:
            p = Process(target=conn, args=(port[i], ))
        pro.append(p)
        p.start()
    for i in range(5):
        pro[i].join()
    print(id, "  over~")
