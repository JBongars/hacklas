import zmq

with zmq.Context() as ctx:
    with ctx.socket(zmq.PUSH) as s:
        s.connect(url)
        s.send_multipart([b"message"])
    # exiting Socket context closes socket
# exiting Context context terminates context
