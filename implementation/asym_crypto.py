from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from datetime import datetime
import binascii

'''
    This module contains all function for asymmetric crypto operations.
    It generates and validates peer ids, signs and the proximity dervied from
    the peer id and the time stamp hash.
'''

# Function to validate a signed msg with the provided public key
def validate_sign(sign, msg, pub_key):
    try:
        pub_key = RSA.importKey(pub_key)
        msg = msg.encode('utf-8')
        hash = SHA256.new(msg)
        signer = PKCS1_v1_5.new(pub_key)
        if signer.verify(hash, sign):
            return True
        return False
    except ValueError:
        print("PublicKey not valid!")
        return False
    except binascii.Error:
        print("PublicKey malformed!")
        return False

# Function to create a sign of a msg with own hostkey
def create_sign(msg, hostkey_path):
    with open(hostkey_path, 'r') as file:
        hostkey = RSA.importKey(file.read())
    msg = msg.encode('utf-8')
    hash = SHA256.new(msg)
    signer = PKCS1_v1_5.new(hostkey)
    signature = signer.sign(hash)
    return signature

# Function to generate the public key from the private hostkey file
def get_pubkey_string(hostkey_path):
    try:
        with open(hostkey_path, 'r') as file:
            hostkey = RSA.importKey(file.read())
        pub_key = hostkey.publickey()
        return pub_key.exportKey(format='PEM')
    except:
        raise Exception("Deriving public key from private hostkey falied!")

# Function to create a peers id from the hostkey
def create_id(pub_key_string):
    try:
        peer_hash = SHA256.new()
        peer_hash.update(pub_key_string)
        peer_id = peer_hash.hexdigest()
        return peer_id
    except:
        raise Exception("Creating Peer ID failed!")

# Function to create a time stamp from the current time
def create_time_stamp_hash():
    try:
        hashed = SHA256.new()
        time = datetime.utcnow().strftime("%Y-%m-%d %H:00:00")
        hash_time = time.encode('utf-8')
        hashed.update(hash_time)
        return hashed.hexdigest()
    except:
        raise Exception("Creating time stamp hash failed!")

# Function to compare the distance between id and time stamp
def compare_binary_digest(time_hash, id):
    try:
        time_bin = bin(int(time_hash, 16))[2:].rjust(256, '0')
        id_bin = bin(int(id, 16))[2:].rjust(256, '0')
        counter = 0
        time_bin_len = len(time_bin)
        while counter < time_bin_len and time_bin[counter] == id_bin[counter]:
            counter+=1
        return counter
    except:
        raise Exception("Comparing binary digest failed!")
