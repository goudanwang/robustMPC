import zmq
 
ctx = zmq.Context.instance()
socket = ctx.socket(zmq.DEALER)
socket.connect("tcp://localhost:12000")
if __name__ == '__main__':
    socket.send(b"hello")
    msg = socket.recv()
    print(msg)