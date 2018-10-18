import struct

'''
    This module contains function for all api protocol messages.
    Moreover, it contains functions to validate nse queries and
    estimate messages.
'''

def nse_query():
    size = 4
    query = 520
    message = struct.pack('!2H',size, query)
    return message


def nse_estimate(est_peers, est_dev):
    size = 12
    estimate = 521
    message = struct.pack('!2H2I',size, estimate, int(est_peers), int(est_dev))
    return message


def validate_query(query):
    try:
        query = struct.unpack('!2H', query)
        if query[0]==4 and query[1]==520:
            return True
        else:
            print("NSE query not valid!")
            return False
    except:
            print("NSE query not valid!")
            return False

def validate_estimate(estimate):
    estimate = struct.unpack('!2H2I', estimate)
    if estimate[0]==12 and estimate[1]==521:
        return True
    else:
        print("NSE estimate not valid!")
        return False
