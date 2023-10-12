from honeybadgermpc.config import HbmpcConfig
from honeybadgermpc.ipc import ProcessProgramRunner, verify_all_connections
from honeybadgermpc.poly_commit_const import gen_pc_const_crs
from honeybadgermpc.hbacss_random_share import Random_share
from honeybadgermpc.hbacss_beaver import Beaver
#from honeybadgermpc.hbacss import get_avss_params, Hbacss1
from honeybadgermpc.betterpairing import ZR, G1, G2
# from pypairing import ZR, G1
import asyncio
import time
import logging, sys

import cProfile, pstats, io

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


# async def _run(peers,pbk, pvk, n, t, my_id, batch_size):
#     alpha, g, ghat, h, pks, sk = load_key(my_id, n)

    
#     print("random sharings generation")
#     async with ProcessProgramRunner(peers, n, t, my_id) as runner:
#         send, recv = runner.get_send_recv("RANDOM_BATCH")
#         crs = gen_pc_const_crs(t, g=g, h=h, ghat = ghat, alpha = alpha)
#         values = [None] * batch_size
#         for i in range(batch_size):
#             values[i] = ZR.random()

#         with Random_share(pks, sk, pbk, pvk, crs, n, t, my_id, send, recv) as random_gen:
#             begin_time = time.time()
#             random_gen_task = asyncio.create_task(
#                 random_gen.avss(0, my_id, values=values)
#                 )
#             random_shares = await random_gen.output_queue.get()
#             end_time = time.time()
#             logger.info(f"time to generate {len(random_shares[0])} random shares: {(end_time - begin_time)}")
#             random_gen_task.cancel()
#         coms = random_shares[0]
#         shares = random_shares[1]
#         auxes = random_shares[2]
#         witnesses = random_shares[3]

#         print("beaver triples generation")
#         batch_size_random = int(len(random_shares[0]) / 2)
#         print("batch_size", batch_size_random)

#         beaver_inputs = (
#             [shares[i] * shares[i + batch_size_random] for i in range(batch_size_random)],
#             ([coms[i] for i in range(batch_size_random)],
#              [witnesses[i] for i in range(batch_size_random)],
#              [shares[i] for i in range(batch_size_random)],
#              [auxes[i] for i in range(batch_size_random)]),
#             ([coms[i] for i in range(batch_size_random, 2 * batch_size_random)],
#              [witnesses[i] for i in range(batch_size_random, 2 * batch_size_random)],
#              [shares[i] for i in range(batch_size_random, 2 * batch_size_random)],
#              [auxes[i] for i in range(batch_size_random, 2 * batch_size_random)])
#         )

#         with Beaver(pks, sk, pbk, pvk, crs, n, t, my_id, send, recv) as beaver:
#             begin_time = time.time()
#             beaver_task = asyncio.create_task(
#                 beaver.avss(1, my_id, values = beaver_inputs)
#                 )
#             c_shares = await beaver.output_queue.get()
#             end_time = time.time()
#             logger.info(f"time to generate {batch_size} beaver triples: {(end_time - begin_time)}")
#             beaver_task.cancel()

async def _run(peers,pbk, pvk, n, t, my_id, batch_size):
    alpha, g, ghat, h, pks, sk = load_key(my_id, n)

    with open('output.txt', 'w') as file:
        sys.stdout = file
        pr = cProfile.Profile()
        pr.enable()

        for j in range(1):
            print("=========", j, "===============")    
            print("random sharings generation")
            async with ProcessProgramRunner(peers, n, t, my_id) as runner:
                send, recv = runner.get_send_recv("RANDOM_BATCH")
                crs = gen_pc_const_crs(t, g=g, h=h, ghat = ghat, alpha = alpha)
                values = [None] * batch_size
                for i in range(batch_size):
                    values[i] = ZR.random()

                with Random_share(pks, sk, pbk, pvk, crs, n, t, my_id, send, recv) as random_gen:
                    begin_time = time.time()
                    random_gen_task = asyncio.create_task(
                        random_gen.avss(0, my_id, values=values)
                        )
                    random_shares = await random_gen.output_queue.get()
                    end_time = time.time()
                    logger.info(f"time to generate {len(random_shares[0])} random shares: {(end_time - begin_time)}")
                    random_gen_task.cancel()
                coms = random_shares[0]
                shares = random_shares[1]
                auxes = random_shares[2]
                witnesses = random_shares[3]

                print("beaver triples generation")
                batch_size_random = int(len(random_shares[0]) / 2)
                print("batch_size", batch_size_random)

                beaver_inputs = (
                    [shares[i] * shares[i + batch_size_random] for i in range(batch_size_random)],
                    ([coms[i] for i in range(batch_size_random)],
                    [witnesses[i] for i in range(batch_size_random)],
                    [shares[i] for i in range(batch_size_random)],
                    [auxes[i] for i in range(batch_size_random)]),
                    ([coms[i] for i in range(batch_size_random, 2 * batch_size_random)],
                    [witnesses[i] for i in range(batch_size_random, 2 * batch_size_random)],
                    [shares[i] for i in range(batch_size_random, 2 * batch_size_random)],
                    [auxes[i] for i in range(batch_size_random, 2 * batch_size_random)])
                )

                with Beaver(pks, sk, pbk, pvk, crs, n, t, my_id, send, recv) as beaver:
                    begin_time = time.time()
                    beaver_task = asyncio.create_task(
                        beaver.avss(1, my_id, values = beaver_inputs)
                        )
                    c_shares = await beaver.output_queue.get()
                    end_time = time.time()
                    logger.info(f"time to generate {batch_size} beaver triples: {(end_time - begin_time)}")
                    beaver_task.cancel()
        pr.disable()
        s = io.StringIO()
        sortby = "cumtime"  # 仅适用于 3.6, 3.7 把这里改成常量了
        ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
        ps.print_stats()

        print(s.getvalue())

        sys.stdout = sys.__stdout__


if __name__ == "__main__":
    asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()
    #HbmpcConfig = HbmpcConfig()
    #print(HbmpcConfig.peers)
    #print(HbmpcConfig.N)
    # loop.run_until_complete(
    #     verify_all_connections(HbmpcConfig.peers, HbmpcConfig.N, HbmpcConfig.my_id))
    # print("verification completed")
    from honeybadgermpc.broadcast.crypto.boldyreva import TBLSPublicKey  # noqa:F401
    from honeybadgermpc.broadcast.crypto.boldyreva import TBLSPrivateKey  # noqa:F401
    import base64

    pbk = pickle.loads(base64.b64decode(HbmpcConfig.extras["public_key"]))
    pvk = pickle.loads(base64.b64decode(HbmpcConfig.extras["private_key"]))
    #print(pbk)

    try:
        loop.run_until_complete(
            _run(
                HbmpcConfig.peers,
                pvk,
                pvk,
                HbmpcConfig.N,
                HbmpcConfig.t,
                HbmpcConfig.my_id,
                HbmpcConfig.extras["k"],
            )
        )
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.warning("run raises an exception", exc_info=True)
    finally:
        loop.close()
