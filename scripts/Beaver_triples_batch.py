from honeybadgermpc.config import HbmpcConfig
from honeybadgermpc.ipc import ProcessProgramRunner, verify_all_connections
from honeybadgermpc.random_share import Random_share
from honeybadgermpc.beaver_triples import Beaver
import asyncio
import time
import logging
import json
import sys
import cProfile, pstats, io

from ctypes import *
lib = CDLL("./gnark-crypto/kzg_ped_out.so")

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
# Uncomment this when you want logs from this file.
logger.setLevel(logging.NOTSET)
import pickle
import os

lib.pySampleSecret.argtypes = [c_int]
lib.pySampleSecret.restype = c_char_p


def load_key(id, N):

    with open(os.getcwd() + '/scripts/keys/' + 'SRS.key', 'rb') as fp:
        SRS = pickle.load(fp)
    
    with open(os.getcwd() + '/scripts/keys/' + 'publicsecretkeys.key', 'rb') as fp:
        publicsecretkeys = pickle.load(fp)
    return SRS, publicsecretkeys




async def _run(peers,pbk, pvk, n, t, my_id, batch_size):
    srs, publicsecretkeys = load_key(my_id, n)
  
    print("random sharings generation")
    # print("SRS", type(srs))
    # print("pks", type(publicsecretkeys))
    
    deserialized_publicsecretkeys = json.loads(publicsecretkeys.decode('utf-8'))
    print(deserialized_publicsecretkeys['secretkeys'])
    pks = json.dumps(deserialized_publicsecretkeys['publickeys']).encode('utf-8')
    sk = json.dumps(deserialized_publicsecretkeys['secretkeys'][my_id]).encode('utf-8')

    with open('outputbeaver.txt', 'w') as file:
        sys.stdout = file
        pr = cProfile.Profile()
        pr.enable()
        
        
        async with ProcessProgramRunner(peers, n, t, my_id) as runner:
            send, recv = runner.get_send_recv("RANDOM_BATCH")
            values = lib.pySampleSecret(batch_size)
            
            with Random_share(pks, sk, pbk, pvk, srs, n, t, my_id, send, recv) as random_gen:
                begin_time = time.time()
                random_gen_task = asyncio.create_task(
                random_gen.avss(0, my_id, "random_share", values=values)
                )
                serialized_com_proof = await random_gen.output_queue.get()
                end_time = time.time()
                time_randomshare = end_time - begin_time
                logger.info(f"time to compute random shares: {(end_time - begin_time)} s")
                random_gen_task.cancel()


            print("beaver triples generation")
    
            with Beaver(pks, sk, pbk, pvk, srs, n, t, my_id, send, recv) as beaver:
                begin_time = time.time()
                beaver_task = asyncio.create_task(
                    beaver.avss(1, my_id, "beaver_triple", values = serialized_com_proof)
                    )
                c_shares = await beaver.output_queue.get()
                end_time = time.time()
                time_beavertriple = end_time - begin_time
                logger.info(f"time to compute beaver triples: {(end_time - begin_time)} s")
                beaver_task.cancel()
            
                logger.info(f"time to generate {batch_size} beaver triples: {(time_beavertriple + time_randomshare)} s")
        
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
