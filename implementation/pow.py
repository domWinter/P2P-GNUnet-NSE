import hashlib
import random
from datetime import datetime

'''
    This module contains all methods needed to create and validate the proof of work
    needed by our nse algorithm.
    A PoW is a hash with n leading 0 from the round-time and a random number.
'''

# Function to create the PoW from the round-time and a random number
def createPoW(num_matches):
    while True:
        int = str(random.getrandbits(64))
        time = str(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
        attempt = int.encode('UTF-8') + time.encode('UTF-8')
        hash = str(hashlib.sha256(attempt).hexdigest())
        if validateHash(hash, num_matches):
            pow = {"Time": time, "Random-number": int, "Hash": hash}
            return pow

# Function to validate a calculated hash
def validateHash(hash, num_matches):
    if hash.startswith(num_matches*"0"):
        return True
    else:
        return False

# Function to validate a PoW
def validatePoW(cur_round, msg_round, pow, num_matches):
    format = '%Y-%m-%d %H:%M:%S'
    pow_round = datetime.strptime(pow["Time"], format).replace(second=0, minute=0)
    cur_round = datetime.strptime(cur_round, format)

    if ((msg_round != pow_round) and (cur_round != pow_round)):
        return False

    attempt = pow["Random-number"] + pow["Time"]
    hash = hashlib.sha256(attempt.encode('utf8')).hexdigest()

    if hash == pow["Hash"] and validateHash(hash, num_matches):
        return True
    else:
        return False
