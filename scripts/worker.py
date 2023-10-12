import zmq
 
if __name__ == '__main__':
    context = zmq.Context()
    socket = context.socket(zmq.DEALER)
    # 设置接收消息超时时间为1秒
    socket.setsockopt(zmq.RCVTIMEO, 1000)
    socket.connect("tcp://localhost:13000")
    # 发送心跳到broker注册worker
    socket.send_multipart([b"heart", b""])
    while True:
        try:
            # 获取客户端地址和消息内容
            client_addr, message = socket.recv_multipart()
        except Exception as e:
            # 超时 重新发送心跳
            print(e)
            socket.send_multipart([b"heart", b""])
            continue
        # 处理任务
        print(client_addr, message)
        # 返回response
        socket.send_multipart([client_addr, b"world"])