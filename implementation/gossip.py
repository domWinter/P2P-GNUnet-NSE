import struct

'''
    This module contains function for all gossip protocol messages.
    Each function returns an assembled gossip message.
'''

def announce(ttl, data_type, data):
    try:
        print("\nGOSSIP ANNOUNCE")
        announce = 500
        res = 0
        size = 8 + len(data)
        format = '!2H2BH' + str(len(data)) + 's'
        message = struct.pack(format, size, announce, ttl, res, data_type, bytes(data.encode('UTF-8')))
        return message
    except:
        raise Exception("Creating gossip announce failed!")

def notify(data_type):
    try:
        print("\nGOSSIP NOTIFY")
        notify = 501
        res = 0
        size = 8
        message = struct.pack('!4H', size, notify, res, data_type)
        return message
    except:
        raise Exception("Creating gossip notify failed!")

def validation(id, valid):
    try:
        print("\nSending GOSSIP VALIDATION:")
        validation = 503
        size = 8
        if valid:
            print(" MESSAGE IS VALID!")
            res = 1
        else:
            print(" MESSAGE IS INVALID!")
            res = 0
        message = struct.pack('!4H',size, validation, id, res)
        return message
    except:
        raise Exception("Creating gossip validation failed!")
