import zmq
context = zmq.Context()
router_socket = context.socket(zmq.ROUTER)
router_socket.bind("tcp://127.0.0.1:5555")
print("aaaa")

while True:
    print("aaaa")
    identity, message = router_socket.recv_multipart()
    print(f"Received message from Dealer {identity.decode()} : {message.decode()}")

    reply_message = f"Reply to {message.decode()}"

    router_socket.send_multipart([identity, reply_message.encode()])