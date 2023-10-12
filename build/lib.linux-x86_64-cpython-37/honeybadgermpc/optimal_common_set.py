# coding=utf-8
from collections import defaultdict
import zfec
import logging
import hashlib
import math
from honeybadgermpc.broadcast.crypto.boldyreva import serialize, deserialize1


logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
# Uncomment this when you want logs from this file.
# logger.setLevel(logging.NOTSET)

async def optimal_common_set(sid, pid, avss_id, n, f, leader, input, pk, sk, receive, send, _setup_rbc, avid_task, _handle_dealer_msgs, rbc_msg, dispersal_msg, flag_set):
    """Reliable broadcast
        :param int pid: ``0 <= pid < N``
        :param int N:  at least 3
        :param int f: fault tolerance, ``N >= 3f + 1``
        :param int leader: ``0 <= leader < N``
        :param input: a proposed set
        :param receive: :func:`receive()` blocks until a message is
            received; message is of the form::
                (i, (tag, ...)) = receive()
            where ``tag`` is one of ``{"VAL", "ECHO", "READY"}``
        :param send: sends (without blocking) a message to a designed
            recipient ``send(i, (tag, ...))``
        :return str: ``m`` after receiving :math:`2f+1` ``READY`` messages
            and :math:`N-2f` ``ECHO`` messages
    """

    def broadcast(o):
        for i in range(n):
            send(i, o)

    if pid == leader:
        # leader broadcasts its input
        broadcast((sid, "1_round", input))

    received = defaultdict(dict)


    while True:
        sender, msg = await receive()
        # Every party signs the first signature if leader's input is contained in its input
        if msg[1] == "1_round":
            for item in msg[2]:
                if item not in input:
                    rbc_msg[item] = await _setup_rbc(item)
                    dispersal_msg[item] = await avid_task[item].retrieve(f"{avss_id}-{item}-B-AVID", pid)
                    if _handle_dealer_msgs(f"{avss_id}-B-AVID", dispersal_msg[item], rbc_msg[item], item):
                        flag_set[item] = True
                        input.add(item)

            def contain(set_a, set_b):
                # assert where B contains A
                for i in set_a:
                    assert i in set_b

            contain(msg[2], input)

            # sign the msg[2]
            h = pk.hash_message(str((sid, "1_round", msg[2])))
            send(leader, (sid, "2_round", pid, serialize(sk.sign(h)), f"{pid}发的消息"))

        # leader collects the signature shares from at least 2f+1 party, then broadcast the signature
        elif msg[1] == "2_round" and pid == leader:
            assert msg[2] in range(n)
            sig_share = deserialize1(msg[3])
            h = pk.hash_message(str((sid, "1_round", input)))
            try:
                pk.verify_share(sig_share, msg[2], h)
            except AssertionError:
                logger.error(f"Signature share failed! {(sid, leader, msg[2], msg[1])}")
                continue

            received[2][msg[2]] = sig_share

            if len(received[2]) == 2 * f + 1:
                sigs = dict(list(received[2].items())[: f + 1])
                sig = pk.combine_shares(sigs)
                assert pk.verify_signature(sig, h)
                broadcast((sid, "3_round", input, serialize(sig)))


        # Every party verify the signature, and then signs the second (confirmed) signature
        elif msg[1] == "3_round":
            sig = deserialize1(msg[3])
            h = pk.hash_message(str((sid, "1_round", msg[2])))
            assert pk.verify_signature(sig, h)

            h_1 = pk.hash_message(str((sid, "3_round", msg[2])))
            send(leader, (sid, "4_round", pid, serialize(sk.sign(h_1))))

        # leader collects the shares of second signature from at least 2f+1 party, then broadcast the signature
        elif msg[1] == "4_round":
            assert msg[2] in range(n)
            sig_share = deserialize1(msg[3])
            h_1 = pk.hash_message(str((sid, "3_round", input)))
            try:
                pk.verify_share(sig_share, msg[2], h_1)
            except AssertionError:
                logger.error(f"Signature share failed! {(sid, pid, msg[2], msg[1])}")
                continue

            received[4][msg[2]] = sig_share

            if len(received[4]) == 2 * f + 1:
                sigs = dict(list(received[4].items())[: f + 1])
                sig = pk.combine_shares(sigs)
                assert pk.verify_signature(sig, h_1)

                broadcast((sid, "5_round", input, serialize(sig)))

        elif msg[1] == "5_round":
            sig = deserialize1(msg[3])
            h = pk.hash_message(str((sid, "3_round", msg[2])))
            assert pk.verify_signature(sig, h)

            return msg[2]
