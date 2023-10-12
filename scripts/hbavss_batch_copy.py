from honeybadgermpc.config import HbmpcConfig
from honeybadgermpc.ipc import ProcessProgramRunner, verify_all_connections
from honeybadgermpc.poly_commit_const import gen_pc_const_crs
from honeybadgermpc.hbacss import get_avss_params, Hbacss1
#from honeybadgermpc.betterpairing import ZR
from pypairing import ZR, G1
import asyncio
import time
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
# Uncomment this when you want logs from this file.
logger.setLevel(logging.NOTSET)


async def _run(peers, n, t, my_id, batch_size):
    g, h, pks, sks = get_avss_params(n + 1, t)
    async with ProcessProgramRunner(peers, n + 1, t, my_id) as runner:
        send, recv = runner.get_send_recv("HBAVSS_BATCH")
        crs = gen_pc_const_crs(t, g=g, h=h)
        values = [None] * (t+1)
        for i in range(t+1):
            values[i] = ZR.random()

        with Hbacss1(pks, sks[my_id], crs, n, t, my_id, send, recv) as hbavss:
            begin_time = time.time()
            hbavss_task = asyncio.create_task(
                hbavss.avss(0, my_id, values=values)
                )
            await hbavss.output_queue.get()
            end_time = time.time()
            print("hhhhhhhhhhhhhhhhhhhhhhhhh")
            logger.info(f"Recipient time: {(end_time - begin_time)}")
            hbavss_task.cancel()
            end_time = time.time()
            logger.info(f"Dealer time: {(end_time - begin_time)}")

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
