from honeybadgermpc.config import HbmpcConfig
from honeybadgermpc.ipc import ProcessProgramRunner, verify_all_connections
from honeybadgermpc.poly_commit_const import gen_pc_const_crs
from honeybadgermpc.hbacss import get_avss_params, Hbacss1
from honeybadgermpc.betterpairing import ZR, G1, G2
# from pypairing import ZR, G1
import asyncio
import time
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
# Uncomment this when you want logs from this file.
logger.setLevel(logging.NOTSET)
import pickle
import os


def load_key(id, N):

    with open(os.getcwd() + '/scripts/keys/' + 'alpha.key', 'rb') as fp:
        alpha = pickle.load(fp)
    
    with open(os.getcwd() + '/scripts/keys/' + 'g.key', 'rb') as fp:
        g = pickle.load(fp)
    
    with open(os.getcwd() + '/scripts/keys/' + 'ghat.key', 'rb') as fp:
        ghat = pickle.load(fp)

    with open(os.getcwd() + '/scripts/keys/' + 'h.key', 'rb') as fp:
        h = pickle.load(fp)

    pks = []
    for i in range(N):
        with open(os.getcwd() + '/scripts/keys/' + 'pks' + str(i) + '.key', 'rb') as fp:
            pks.append(pickle.load(fp))

    with open(os.getcwd() + '/scripts/keys/' + 'sks' + str(id) + '.key', 'rb') as fp:
        sk = pickle.load(fp)

    return alpha, g, ghat, h, pks, sk


async def _run(peers, n, t, my_id, batch_size):
    alpha, g, ghat, h, pks, sk = load_key(my_id, n)

    async with ProcessProgramRunner(peers, n, t, my_id) as runner:
        send, recv = runner.get_send_recv("HBAVSS_BATCH")
        crs = gen_pc_const_crs(t, g=g, h=h, ghat = ghat, alpha = alpha)
        values = [None] * batch_size
        for i in range(batch_size):
            values[i] = ZR.random()

        with Hbacss1(pks, sk, crs, n, t, my_id, send, recv) as hbavss:
            begin_time = time.time()
            hbavss_task = asyncio.create_task(
                hbavss.avss(0, my_id, values=values)
                )
            await hbavss.output_queue.get()
            end_time = time.time()
            logger.info(f"time to generate {batch_size} shares: {(end_time - begin_time)}")
            hbavss_task.cancel()
            #end_time = time.time()
            #logger.info(f"Dealer time: {(end_time - begin_time)}")

    #values = [[ZR.random()] * (t + 1)] * n
    #print(values)


if __name__ == "__main__":
    asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()
    #HbmpcConfig = HbmpcConfig()
    #print(HbmpcConfig.peers)
    #print(HbmpcConfig.N)
    # loop.run_until_complete(
    #     verify_all_connections(HbmpcConfig.peers, HbmpcConfig.N, HbmpcConfig.my_id))
    # print("verification completed")

    try:
        loop.run_until_complete(
            _run(
                HbmpcConfig.peers,
                HbmpcConfig.N,
                HbmpcConfig.t,
                HbmpcConfig.my_id,
                HbmpcConfig.extras["k"],
            )
        )
    finally:
        loop.close()
