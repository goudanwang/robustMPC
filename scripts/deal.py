import zmq

context = zmq.Context()

dealer1 = context.socket(zmq.DEALER)
dealer1.identity = b"Dealer1"
dealer1.connect("tcp://127.0.0.1:5555")

dealer2 = context.socket(zmq.DEALER)
dealer2.identity = b"Dealer2"
dealer2.connect("tcp://127.0.0.1:5555")
print("bbbb")
for i in range(5):
    request_message = f"Request {i + 1}"
    if i % 2 == 0:
        dealer1.send(request_message.encode())
    else:
        dealer2.send(request_message.encode())
print("bbbb")

for i in range(5):
    if i % 2 == 0:
        reply_message = dealer1.recv()
    else:
        reply_message = dealer2.recv()
    print(f"Received reply from Router: {reply_message.decode()}")
print("bbbb")
dealer1.close()
dealer2.close()
context.term()