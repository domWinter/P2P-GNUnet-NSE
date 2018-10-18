import unittest
import configparser
import os,sys,inspect
import struct

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir)
dir = os.path.dirname(os.path.realpath(__file__))

from parser import GossipParser
from asym_crypto import *
from pow import *
from time_delay import *
from gossip import *
from nse_prot_message import *
from api_message import *

'''
    This module contains all test cases for the nse program as unittests.
    To run the tests execute:
        python3 tests.py
    from the same directory as the file!
'''

class Test(unittest.TestCase):


    '''
        Test cases for parsing the config file
    '''
    def test_parser_wrong_config_path(self):
        with self.assertRaises(Exception) as context:
            GossipParser("")
        self.assertTrue('Failed to parse config ini, check path!' in str(context.exception))

    def test_parser_wrong_config(self):
        with self.assertRaises(Exception) as context:
            GossipParser(dir + "/" + "config_error.ini")
        self.assertTrue("Parsed config does not contain all needed values!" in str(context.exception))

    def test_parser_gossip_bootstrapper_address(self):
        config = GossipParser(dir + "/" + "config.ini")
        self.assertEqual(config.gossip_bootstrapper_address, '127.0.0.1')

    def test_parser_gossip_bootstrapper_port(self):
        config = GossipParser(dir + "/" + "config.ini")
        self.assertEqual(config.gossip_bootstrapper_port, '6001')

    def test_parser_gossip_listen_address(self):
        config = GossipParser(dir + "/" + "config.ini")
        self.assertEqual(config.gossip_listen_address, '127.0.0.1')

    def test_parser_gossip_listen_port(self):
        config = GossipParser(dir + "/" + "config.ini")
        self.assertEqual(config.gossip_listen_port, '6001')

    def test_parser_gossip_api_address(self):
        config = GossipParser(dir + "/" + "config.ini")
        self.assertEqual(config.gossip_api_address, '127.0.0.1')

    def test_parser_gossip_api_port(self):
        config = GossipParser(dir + "/" + "config.ini")
        self.assertEqual(config.gossip_api_port, '7001')

    def test_parser_nse_listen_address(self):
        config = GossipParser(dir + "/" + "config.ini")
        self.assertEqual(config.nse_listen_address, '127.0.0.1')

    def test_parser_nse_listen_port(self):
        config = GossipParser(dir + "/" + "config.ini")
        self.assertEqual(config.nse_listen_port, '6201')

    def test_parser_nse_api_address(self):
        config = GossipParser(dir + "/" + "config.ini")
        self.assertEqual(config.nse_api_address, '127.0.0.1')

    def test_parser_nse_api_port(self):
        config = GossipParser(dir + "/" + "config.ini")
        self.assertEqual(config.nse_api_port, '7201')

    def test_parser_nse_mockup_estimate_max(self):
        config = GossipParser(dir + "/" + "config.ini")
        self.assertEqual(config.nse_mockup_estimate_max, '50')

    def test_parser_nse_mockup_deviation_max(self):
        config = GossipParser(dir + "/" + "config.ini")
        self.assertEqual(config.nse_mockup_deviation_max, '5')

    def test_parser_nse_pow_num_bits(self):
        config = GossipParser(dir + "/" + "config.ini")
        self.assertEqual(config.nse_pow_num_bits, '4')

    '''
        Test cases for asymmetric crypto operations
    '''
    def test_get_public_key_string(self):
        key = r"b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu/FbAdgsoVw5EqwU8GKl\n5E76pujBwXpeNq78zMgdWD2/znWJKCG9obWgHrczVD9yaFSSAXca87NW7L7Mm8ft\nGZo8Lrh9xTTl+qDWNngeLuE97l+D7jZtdTexuEmoZWbggxXNGwDACdeAxYVGvkJN\nf6gnD5uqmWBUhZOIeJrRuzX2qxDax6DMXtPaZSeP0GKIIS8URJIoElvYvFOAAs0u\np2oqLVW5tyVf2C9y5LW/0tTvfTeDh92FkJhcdelZD89faaP6knyQTwmi2fUtropT\nbX8FcgD/pTy/8Lu2NtkII3chDXJW1eOn3CAVTPg8VtaUIPxG1eC9o3LbdnU7+2m4\njQIDAQAB\n-----END PUBLIC KEY-----'"
        pub_key = get_pubkey_string(dir + "/" + "hostkey.pem")
        self.assertEqual(str(pub_key), key)

    def test_create_id(self):
        id = "ea349a4d18ba22187da29a838b157bc342a7c3d83518f5a2a6ce29eb071449dc"
        pub_key = get_pubkey_string(dir + "/" + "hostkey.pem")
        self.assertEqual(create_id(pub_key), id)

    def test_compare_binary_digest_small(self):
        id = "ea349a4d18ba22187da29a838b157bc342a7c3d83518f5a2a6ce29eb071449dc"
        time_hash = "ff451704f5d7fa9275ac797cbfabf9f43f9a24d68233c3eee533c0ac1dc76cdb"
        self.assertEqual(compare_binary_digest(time_hash, id), 3)

    def test_compare_binary_digest_same(self):
        id = "ea349a4d18ba22187da29a838b157bc342a7c3d83518f5a2a6ce29eb071449dc"
        time_hash = "ea349a4d18ba22187da29a838b157bc342a7c3d83518f5a2a6ce29eb071449dc"
        self.assertEqual(compare_binary_digest(time_hash, id), 256)

    def test_create_sign(self):
        sign = r"b'*:\x9f\x05\x84\xfd\xa2\x1e\xf5l\xcbh\xfd\xed}\x87\x93f\x14\xe9\xfc\\\x86\x18\xba\xb7\x07\xf5\xf5>\xa4\xa0\xce\xa9\x7f\xcd.F\x82\x15\xcds\xf1}\x1ex\x7f\xe6\x07\x1d\xb6\x92\xa1*x-\xd6\x16@\xfb\x171\x9a)\x03\x87\xbd\xe6KA\xea\xa0\x8e\xb4a\x1e3\x8b\xaev\xdf\x11]\xea.\xcc\xd7X\x9d\xd5 \xd0\xf8\xb3\xde\xa9\x83I\xa3ZC\x90\xb6Y\x06\xba\x83x\x81u`~\x96}\x10\xdf\x1b*\xef\x07\\ \x9f\x07\x9a\xfa\xafL$.\xe59\x94\xd1\x19\xcf\xfb[\\\xactB)0\x00\xf1iYQ\xf0\xb7\x93\x01K\xf0\x15EN\xa6\xa3KsK1\xfe\x1b\xffF\xa09\xae\xbd\xdb\x1a\xcaz\x1dgp%\x12\x9d\xdcP\x8a(\xef\xfa\x06\x9ctj\xbde\xf8\xd8y\x05\xd0\x12\x96\xe5\x8f\x13G\xdeD\xa8n7\x10}\xf3R\xa1<DOQ\xb6v\xe5\xe6\x97f@lNu\x82\x8a\xe5\xa7L\x89\xeeE\x82\xa4\x9935\x0c\x01\xc8\xe4\xbf\xb1\x8d\xc2t\x92\x8bPk2'"
        self.assertEqual(str(create_sign("Test", dir + "/" + "hostkey.pem")), sign)

    def test_validate_sign_same(self):
        sign = create_sign("Test", dir + "/" + "hostkey.pem")
        msg = "Test"
        pub_key = get_pubkey_string(dir + "/" + "hostkey.pem")
        self.assertEqual(validate_sign(sign, msg, pub_key), True)

    def test_validate_sign_altered_msg(self):
        sign = create_sign("Test", dir + "/" + "hostkey.pem")
        msg = "Test_different"
        pub_key = get_pubkey_string(dir + "/" + "hostkey.pem")
        self.assertEqual(validate_sign(sign, msg, pub_key), False)

    def test_validate_sign_altered_hostkey(self):
        sign = create_sign("Test", dir + "/" + "hostkey_different.pem")
        msg = "Test"
        pub_key = get_pubkey_string(dir + "/" + "hostkey.pem")
        self.assertEqual(validate_sign(sign, msg, pub_key), False)

    '''
        Test cases for proof of work
    '''
    def test_create_pow_simple(self):
        pow = createPoW(2)
        self.assertEqual(len(pow), 3)
        self.assertTrue(pow["Hash"].startswith(2*"0"))

    def test_create_pow_difficult(self):
        pow = createPoW(4)
        self.assertEqual(len(pow), 3)
        self.assertTrue(pow["Hash"].startswith(4*"0"))

    def test_validate_pow_correct(self):
        pow = { 'Time' : '2018-07-24 18:06:46', 'Random-number' : '17324191847119623674', 'Hash' : '000036a541d49e042d73d2fd6c914135a8ff55430f43953b31659ea8d6e05b86' }
        cur_round = '2018-07-24 18:00:00'
        msg_round = '2018-07-24 18:00:00'
        num_matches = 4
        self.assertTrue(validatePoW(cur_round, msg_round, pow, num_matches))

    def test_validate_pow_correct_diff_rounds(self):
        pow = { 'Time' : '2018-07-24 18:06:46', 'Random-number' : '17324191847119623674', 'Hash' : '000036a541d49e042d73d2fd6c914135a8ff55430f43953b31659ea8d6e05b86' }
        cur_round = '2018-07-24 18:00:00'
        msg_round = '2018-07-24 19:00:00'
        num_matches = 4
        self.assertTrue(validatePoW(cur_round, msg_round, pow, num_matches))

    def test_validate_pow_wrong_hash(self):
        pow = { 'Time' : '2018-07-24 18:06:46', 'Random-number' : '17324191847119623674', 'Hash' : '000236a541d49e042d73d2fd6c914135a8ff55430f43953b31659ea8d6e05b86' }
        cur_round = '2018-07-24 18:00:00'
        msg_round = '2018-07-24 18:00:00'
        num_matches = 4
        self.assertFalse(validatePoW(cur_round, msg_round, pow, num_matches))

    def test_validate_pow_wrong_rand(self):
        pow = { 'Time' : '2018-07-24 18:06:46', 'Random-number' : '17224191847119623674', 'Hash' : '000036a541d49e042d73d2fd6c914135a8ff55430f43953b31659ea8d6e05b86' }
        cur_round = '2018-07-24 18:00:00'
        msg_round = '2018-07-24 18:00:00'
        num_matches = 4
        self.assertFalse(validatePoW(cur_round, msg_round, pow, num_matches))

    def test_validate_pow_wrong_time(self):
        pow = { 'Time' : '2018-07-24 18:06:45', 'Random-number' : '17224191847119623674', 'Hash' : '000036a541d49e042d73d2fd6c914135a8ff55430f43953b31659ea8d6e05b86' }
        cur_round = '2018-07-24 18:00:00'
        msg_round = '2018-07-24 18:00:00'
        num_matches = 4
        self.assertFalse(validatePoW(cur_round, msg_round, pow, num_matches))

    def test_validate_pow_wrong_round1(self):
        pow = { 'Time' : '2018-07-24 18:06:46', 'Random-number' : '17224191847119623674', 'Hash' : '000036a541d49e042d73d2fd6c914135a8ff55430f43953b31659ea8d6e05b86' }
        cur_round = '2018-07-24 20:00:00'
        msg_round = '2018-07-24 18:00:00'
        num_matches = 4
        self.assertFalse(validatePoW(cur_round, msg_round, pow, num_matches))

    def test_validate_pow_wrong_round2(self):
        pow = { 'Time' : '2018-07-24 18:06:46', 'Random-number' : '17224191847119623674', 'Hash' : '000036a541d49e042d73d2fd6c914135a8ff55430f43953b31659ea8d6e05b86' }
        cur_round = '2018-07-24 18:00:00'
        msg_round = '2018-07-24 19:00:00'
        num_matches = 4
        self.assertFalse(validatePoW(cur_round, msg_round, pow, num_matches))


    '''
        Test cases gossip
    '''
    def test_gossip_announce(self):
        msg = announce(15, 530, "Test")
        self.assertEqual(msg[0], 0)
        self.assertEqual(msg[1], 12)   # Size = 12 bytes
        self.assertEqual(msg[2], 1)    # Announce = 500 = 0x1f4
        self.assertEqual(msg[3], 244)  # 0xf4 = 244
        self.assertEqual(msg[4], 15)   # TTL = 15
        self.assertEqual(msg[5], 0)    # RES = 0
        self.assertEqual(msg[6], 2)    # Data type = 530 = 0x212
        self.assertEqual(msg[7], 18)   # 0x12 = 18
        self.assertEqual(msg[8], 84)   # T
        self.assertEqual(msg[9], 101)  # e
        self.assertEqual(msg[10], 115) # s
        self.assertEqual(msg[11], 116) # t

    def test_gossip_notify(self):
        msg = notify(530)
        self.assertEqual(msg[0], 0)
        self.assertEqual(msg[1], 8)   # Size = 8 bytes
        self.assertEqual(msg[2], 1)   # Notify = 501 = 0x1f5
        self.assertEqual(msg[3], 245) # 0xf5 = 245
        self.assertEqual(msg[4], 0)   # res
        self.assertEqual(msg[5], 0)   # res
        self.assertEqual(msg[6], 2)   # Data type = 530 = 0x212
        self.assertEqual(msg[7], 18)  # 0x12 = 18

    def test_gossip_validation_valid(self):
        msg = validation(65535, True)
        self.assertEqual(msg[0], 0)
        self.assertEqual(msg[1], 8)   # Size = 8 bytes
        self.assertEqual(msg[2], 1)   # Notify = 503 = 0x1f7
        self.assertEqual(msg[3], 247) # 0xf7 = 247
        self.assertEqual(msg[4], 255) # ID = 0xffff
        self.assertEqual(msg[5], 255) # ID = 0xffff
        self.assertEqual(msg[6], 0)   # RES
        self.assertEqual(msg[7], 1)   # Valid

    def test_gossip_validation_invalid(self):
        msg = validation(65535, False)
        self.assertEqual(msg[0], 0)
        self.assertEqual(msg[1], 8)   # Size = 8 bytes
        self.assertEqual(msg[2], 1)   # Notify = 503 = 0x1f7
        self.assertEqual(msg[3], 247) # 0xf7 = 247
        self.assertEqual(msg[4], 255) # ID = 0xffff
        self.assertEqual(msg[5], 255) # ID = 0xffff
        self.assertEqual(msg[6], 0)   # RES
        self.assertEqual(msg[7], 0)   # Invalid


    '''
        Test cases for time delays
    '''
    def test_create_flood_delay_empty_msg_history_hour_freq(self):
        msg_history = []
        cur_prox = 1
        freq=3600
        delay1 = create_flood_delay(msg_history, cur_prox, freq)
        self.assertEqual(delay1, 900)

    def test_create_flood_delay_empty_msg_history_minute_freq(self):
        msg_history = []
        cur_prox = 1
        freq=60
        delay1 = create_flood_delay(msg_history, cur_prox, freq)
        self.assertEqual(delay1, 15)

    def test_create_flood_delay_filled_msg_history_hour_freq(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 2)
        handler.proximity = 1
        json_msg = handler.create_msg(15, handler.round, handler.proximity)
        handler.msg_history.append(json_msg)
        cur_prox = 2
        freq=3600
        delay1 = create_flood_delay(handler.msg_history, cur_prox, freq)
        self.assertEqual(delay1, 900)

    def test_create_flood_delay_filled_msg_history_minute_freq(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 2)
        handler.proximity = 1
        json_msg = handler.create_msg(15, handler.round, handler.proximity)
        handler.msg_history.append(json_msg)
        cur_prox = 2
        freq=60
        delay1 = create_flood_delay(handler.msg_history, cur_prox, freq)
        self.assertEqual(delay1, 15)

    def test_create_flood_delay_filled_msg_history_euqal_prox(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 2)
        handler.proximity = 1
        json_msg = handler.create_msg(15, handler.round, handler.proximity)
        handler.msg_history.append(json_msg)
        cur_prox = 1
        freq=3600
        delay1 = create_flood_delay(handler.msg_history, cur_prox, freq)
        self.assertEqual(delay1, 1800)

    def test_create_flood_delay_filled_msg_history_worse_prox(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 2)
        handler.proximity = 2
        json_msg = handler.create_msg(15, handler.round, handler.proximity)
        handler.msg_history.append(json_msg)
        cur_prox = 1
        freq=3600
        delay1 = create_flood_delay(handler.msg_history, cur_prox, freq)
        self.assertEqual(delay1, 2700)

    def test_create_flood_delay_different_prox_positiv(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 2)
        handler.proximity = 0
        json_msg = handler.create_msg(15, handler.round, handler.proximity)
        handler.msg_history.append(json_msg)
        cur_prox = 250
        freq=3600
        delay1 = create_flood_delay(handler.msg_history, cur_prox, freq)
        self.assertEqual(delay1, 4.583637915081908)

    def test_create_flood_delay_different_prox_negativ(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 2)
        handler.proximity = 250
        json_msg = handler.create_msg(15, handler.round, handler.proximity)
        handler.msg_history.append(json_msg)
        cur_prox = 0
        freq = 3600
        delay1 = create_flood_delay(handler.msg_history, cur_prox, freq)
        self.assertEqual(delay1, 3595.416362084918)

    def test_create_processing_delay_check_randomness(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 2)
        handler.proximity = 1
        json_msg = handler.create_msg(15, handler.round, handler.proximity)
        handler.msg_history.append(json_msg)
        cur_prox = 2
        freq = 3600
        delay1 = create_processing_delay(handler.msg_history,cur_prox,freq,handler.max_hop_count)
        delay2 = create_processing_delay(handler.msg_history,cur_prox,freq,handler.max_hop_count)
        self.assertNotEqual(delay1, delay2)


    def test_create_processing_delay_is_in_range(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 2)
        handler.proximity = 1
        json_msg = handler.create_msg(15, handler.round, handler.proximity)
        handler.msg_history.append(json_msg)
        cur_prox = 2
        freq = 3600
        delay1 = create_processing_delay(handler.msg_history,cur_prox,freq,handler.max_hop_count)
        self.assertTrue(0 <= delay1 and delay1 <= 900)

    def test_create_processing_delay_hop_count_is_zero(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 2)
        handler.proximity = 1
        json_msg = handler.create_msg(0, handler.round, handler.proximity)
        handler.msg_history.append(json_msg)
        cur_prox = 2
        freq = 3600
        delay1 = create_processing_delay(handler.msg_history,cur_prox,freq,handler.max_hop_count)
        self.assertTrue(0 <= delay1 and delay1 <= 56.25)

    def test_create_processing_delay_msg_history_is_empty(self):
        msg_history = []
        cur_prox = 1
        freq = 3600
        delay1 = create_processing_delay(msg_history,cur_prox,freq,15)
        self.assertTrue(0 <= delay1 and delay1 <= 900)

    def test_create_processing_delay_high_proximity(self):
        msg_history = []
        cur_prox = 250
        freq = 3600
        delay1 = create_processing_delay(msg_history,cur_prox,freq,15)
        self.assertTrue(0 <= delay1 and delay1 <= 0.018407986862484904)

    def test_create_processing_delay_check_randomness_minute_freq(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 2)
        handler.proximity = 1
        json_msg = handler.create_msg(15, handler.round, handler.proximity)
        handler.msg_history.append(json_msg)
        cur_prox = 2
        freq = 60
        delay1 = create_processing_delay(handler.msg_history,cur_prox,freq,handler.max_hop_count)
        delay2 = create_processing_delay(handler.msg_history,cur_prox,freq,handler.max_hop_count)
        self.assertNotEqual(delay1, delay2)

    def test_create_processing_delay_is_in_range_minute_freq(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 2)
        handler.proximity = 1
        json_msg = handler.create_msg(15, handler.round, handler.proximity)
        handler.msg_history.append(json_msg)
        cur_prox = 2
        freq = 60
        delay1 = create_processing_delay(handler.msg_history,cur_prox,freq,handler.max_hop_count)
        self.assertTrue(0 <= delay1 and delay1 <= 15)

    def test_create_processing_delay_hop_count_is_zero_minute_freq(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 2)
        handler.proximity = 1
        json_msg = handler.create_msg(0, handler.round, handler.proximity)
        handler.msg_history.append(json_msg)
        cur_prox = 2
        freq = 60
        delay1 = create_processing_delay(handler.msg_history,cur_prox,freq,handler.max_hop_count)
        self.assertTrue(0 <= delay1 and delay1 <= 0.9375)

    def test_create_processing_delay_msg_history_is_empty_minute_freq(self):
        msg_history = []
        cur_prox = 1
        freq = 60
        delay1 = create_processing_delay(msg_history,cur_prox,freq,15)
        self.assertTrue(0 <= delay1 and delay1 <= 15)

    def test_create_processing_delay_high_proximity_minute_freq(self):
        msg_history = []
        cur_prox = 250
        freq = 60
        delay1 = create_processing_delay(msg_history,cur_prox,freq,15)
        self.assertTrue(0 <= delay1 and delay1 <= 0.00030679978103975714)

    '''
        Test cases for nse_prot_message
    '''
    def test_nse_handler_msg_history(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        self.assertEqual(len(handler.msg_history), 0)

    def test_nse_handler_hostkey(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        self.assertEqual(handler.hostkey_path, dir + "/" + "hostkey.pem")

    def test_nse_handler_pubkey(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        key = r"b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu/FbAdgsoVw5EqwU8GKl\n5E76pujBwXpeNq78zMgdWD2/znWJKCG9obWgHrczVD9yaFSSAXca87NW7L7Mm8ft\nGZo8Lrh9xTTl+qDWNngeLuE97l+D7jZtdTexuEmoZWbggxXNGwDACdeAxYVGvkJN\nf6gnD5uqmWBUhZOIeJrRuzX2qxDax6DMXtPaZSeP0GKIIS8URJIoElvYvFOAAs0u\np2oqLVW5tyVf2C9y5LW/0tTvfTeDh92FkJhcdelZD89faaP6knyQTwmi2fUtropT\nbX8FcgD/pTy/8Lu2NtkII3chDXJW1eOn3CAVTPg8VtaUIPxG1eC9o3LbdnU7+2m4\njQIDAQAB\n-----END PUBLIC KEY-----'"
        self.assertEqual(str(handler.public_key_string), key)

    def test_nse_handler_id(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        self.assertEqual(handler.id, "ea349a4d18ba22187da29a838b157bc342a7c3d83518f5a2a6ce29eb071449dc")

    def test_nse_handler_pow_num_bits(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        self.assertEqual(handler.pow_num_bits, 3)

    def test_nse_handler_est_std_deviation(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        self.assertEqual(handler.est_std_deviation, 0)

    def test_nse_handler_msg(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        self.assertEqual(json.loads(handler.msg)["Hop-Count"], '15')

    def test_nse_handler_pow(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        self.assertTrue(handler.PoW["Hash"].startswith(3*"0"))

    def test_nse_handler_create_round_msg_future_better(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        future_msg = json.loads(handler.msg)
        future_msg["Proximity"] = 200
        handler.future_msg = future_msg
        handler.create_round_msg()
        self.assertEqual(json.loads(handler.msg)["Proximity"], "200")

    def test_nse_handler_create_round_msg_future_worse(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        prox = json.loads(handler.msg)["Proximity"]
        future_msg = json.loads(handler.msg)
        future_msg["Proximity"] = -1
        handler.future_msg = future_msg
        handler.create_round_msg()
        self.assertEqual(json.loads(handler.msg)["Proximity"], str(prox))

    def test_nse_handler_create_msg(self):
        key = r"b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu/FbAdgsoVw5EqwU8GKl\n5E76pujBwXpeNq78zMgdWD2/znWJKCG9obWgHrczVD9yaFSSAXca87NW7L7Mm8ft\nGZo8Lrh9xTTl+qDWNngeLuE97l+D7jZtdTexuEmoZWbggxXNGwDACdeAxYVGvkJN\nf6gnD5uqmWBUhZOIeJrRuzX2qxDax6DMXtPaZSeP0GKIIS8URJIoElvYvFOAAs0u\np2oqLVW5tyVf2C9y5LW/0tTvfTeDh92FkJhcdelZD89faaP6knyQTwmi2fUtropT\nbX8FcgD/pTy/8Lu2NtkII3chDXJW1eOn3CAVTPg8VtaUIPxG1eC9o3LbdnU7+2m4\njQIDAQAB\n-----END PUBLIC KEY-----'"
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        msg = handler.create_msg(15, '2018-07-24 18:00:00', 20)
        self.assertEqual(msg["Hop-Count"], "15")
        self.assertEqual(msg["Round"], "2018-07-24 18:00:00")
        self.assertEqual(msg["Proximity"], "20")
        self.assertEqual(msg["Pub-key"], key)
        self.assertTrue(msg["PoW"]["Hash"].startswith(3*"0"))
        self.assertTrue(len(msg["Sign"])>10)

    def test_nse_handler_append_msg_to_history(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        handler.append_msg_to_history()
        self.assertEqual(len(handler.msg_history), 1)

    def test_nse_handler_append_msg_to_history_15(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        for i in range(0,20):
            handler.append_msg_to_history()
        self.assertEqual(len(handler.msg_history), 15)

    def test_nse_handler_calc_estimation(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        est = handler.calc_estimation(10)
        self.assertEqual(est, 813)

    def test_nse_handler_validate_msg(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        msg = (handler.msg).encode("UTF-8")
        self.assertTrue(handler.validate_msg(msg))

    def test_nse_handler_validate_msg_hop_count_range(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        msg = json.loads(handler.msg)
        msg["Hop-Count"] = "6000"
        msg = (json.dumps(msg)).encode("UTF-8")
        self.assertFalse(handler.validate_msg(msg))

    def test_nse_handler_validate_msg_round_malformed(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        msg = json.loads(handler.msg)
        msg["Round"] = '2018-07-24 18:00:00:0'
        msg = (json.dumps(msg)).encode("UTF-8")
        self.assertFalse(handler.validate_msg(msg))

    def test_nse_handler_validate_msg_round_no_string(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        msg = json.loads(handler.msg)
        msg["Round"] = {'Round' : '2018-07-24 18:00:00'}
        msg = (json.dumps(msg)).encode("UTF-8")
        self.assertFalse(handler.validate_msg(msg))

    def test_nse_handler_validate_msg_proximity_range(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        msg = json.loads(handler.msg)
        msg["Proximity"] = "257"
        msg = (json.dumps(msg)).encode("UTF-8")
        self.assertFalse(handler.validate_msg(msg))

    def test_nse_handler_validate_msg_proximity_not_correct(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        msg = json.loads(handler.msg)
        msg["Proximity"] = "200"
        msg = (json.dumps(msg)).encode("UTF-8")
        self.assertFalse(handler.validate_msg(msg))

    def test_nse_handler_validate_msg_proximity_wrong_key_for_sign(self):
        key = r"b'-----BEGIN PUBLIC KEY-----\nNIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu/FbAdgsoVw5EqwU8GKl\n5E76pujBwXpeNq78zMgdWD2/znWJKCG9obWgHrczVD9yaFSSAXca87NW7L7Mm8ft\nGZo8Lrh9xTTl+qDWNngeLuE97l+D7jZtdTexuEmoZWbggxXNGwDACdeAxYVGvkJN\nf6gnD5uqmWBUhZOIeJrRuzX2qxDax6DMXtPaZSeP0GKIIS8URJIoElvYvFOAAs0u\np2oqLVW5tyVf2C9y5LW/0tTvfTeDh92FkJhcdelZD89faaP6knyQTwmi2fUtropT\nbX8FcgD/pTy/8Lu2NtkII3chDXJW1eOn3CAVTPg8VtaUIPxG1eC9o3LbdnU7+2m4\njQIDAQAB\n-----END PUBLIC KEY-----'"
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        msg = json.loads(handler.msg)
        msg["Pub-key"] = key
        msg = (json.dumps(msg)).encode("UTF-8")
        self.assertFalse(handler.validate_msg(msg))

    def test_nse_handler_validate_msg_pow_wrong(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        msg = json.loads(handler.msg)
        msg["PoW"]["Random-number"] = 1
        msg = (json.dumps(msg)).encode("UTF-8")
        self.assertFalse(handler.validate_msg(msg))

    def test_nse_handler_update_better_msg(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        msg = json.loads(handler.msg)
        msg["Proximity"] = 200
        self.assertTrue(handler.update_msg(json.dumps(msg), 3600))
        self.assertEqual(handler.proximity, 200)

    def test_nse_handler_update_worse_msg(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        prox = handler.proximity
        msg = json.loads(handler.msg)
        msg["Proximity"] = -1
        self.assertFalse(handler.update_msg(json.dumps(msg), 3600))
        self.assertEqual(handler.proximity, prox)

    def test_nse_handler_update_better_msg_hop_count_1(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        prox = handler.proximity
        msg = json.loads(handler.msg)
        msg["Proximity"] = 200
        msg["Hop-Count"] = 1
        self.assertFalse(handler.update_msg(json.dumps(msg), 3600))
        self.assertEqual(handler.proximity, 200)

    def test_nse_handler_update_msg_one_round_behind(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        prox = handler.proximity
        msg = json.loads(handler.msg)
        msg["Round"] = '2018-07-24 18:00:00'
        handler.msg = json.dumps(msg)
        msg["Round"] = '2018-07-24 17:00:00'
        self.assertTrue(len(handler.msg_history)==0)
        self.assertTrue(handler.update_msg(json.dumps(msg), 3600))
        self.assertTrue(len(handler.msg_history)>0)

    def test_nse_handler_update_msg_one_round_before(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        prox = handler.proximity
        msg = json.loads(handler.msg)
        msg["Round"] = '2018-07-24 17:00:00'
        handler.msg = json.dumps(msg)
        msg["Round"] = '2018-07-24 18:00:00'
        self.assertTrue(len(handler.future_msg)==0)
        self.assertFalse(handler.update_msg(json.dumps(msg), 3600))
        self.assertTrue(len(handler.future_msg)>0)

    def test_nse_handler_update_msg_two_round_before(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        prox = handler.proximity
        msg = json.loads(handler.msg)
        msg["Round"] = '2018-07-24 17:00:00'
        handler.msg = json.dumps(msg)
        msg["Round"] = '2018-07-24 19:00:00'
        self.assertTrue(len(handler.future_msg)==0)
        self.assertFalse(handler.update_msg(json.dumps(msg), 3600))
        self.assertTrue(len(handler.future_msg)==0)

    def test_nse_handler_update_msg_two_round_behind(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        prox = handler.proximity
        msg = json.loads(handler.msg)
        msg["Round"] = '2018-07-24 19:00:00'
        handler.msg = json.dumps(msg)
        msg["Round"] = '2018-07-24 17:00:00'
        self.assertTrue(len(handler.msg_history)==0)
        self.assertFalse(handler.update_msg(json.dumps(msg), 3600))
        self.assertTrue(len(handler.msg_history)==0)

    def test_nse_handler_update_msg_hop_count_1(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        prox = handler.proximity
        msg = json.loads(handler.msg)
        msg["Round"] = '2018-07-24 19:00:00'
        handler.msg = json.dumps(msg)
        msg["Round"] = '2018-07-24 18:00:00'
        msg["Hop-Count"] = '1'
        self.assertTrue(len(handler.msg_history)==0)
        self.assertFalse(handler.update_msg(json.dumps(msg), 3600))
        self.assertTrue(len(handler.msg_history)==1)


    def test_std_deviation_empty_history(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        self.assertTrue(handler.create_std_deviation()==0)

    def test_std_deviation_equal_proximities(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        handler.proximity = 3
        msg= handler.create_msg(15, handler.round, 3)
        handler.msg_history.append(msg)
        self.assertTrue(handler.create_std_deviation()==0)

    def test_std_deviation_equal_proximities_various_msgs(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        handler.proximity = 3
        msg= handler.create_msg(15, handler.round, 3)
        for i in range(15):
            handler.msg_history.append(msg)
        self.assertTrue(handler.create_std_deviation()==0)

    def test_std_deviation_different_proximities(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        handler.proximity = 5
        msg= handler.create_msg(15, handler.round, 2)
        handler.msg_history.append(msg)
        std = handler.create_std_deviation()
        self.assertTrue(handler.create_std_deviation()==15.556349186104045)

    def test_std_deviation_different_proximities_various_msgs(self):
        handler = NSEHandler(dir + "/" + "hostkey.pem", 3)
        handler.proximity = 15
        for i in range(15):
            msg= handler.create_msg(15, handler.round, i)
            handler.msg_history.append(msg)
        dev=handler.create_std_deviation()
        print(dev)
        self.assertTrue(handler.create_std_deviation()==6992.366969000316)

    '''
        Test cases for api message
    '''

    def test_nse_query(self):
        msg = nse_query()
        self.assertEqual(msg[0], 0)
        self.assertEqual(msg[1], 4)   # Size = 4 bytes
        self.assertEqual(msg[2], 2)   # Query = 520 = 0x208
        self.assertEqual(msg[3], 8)   # 0x08 = 8

    def test_nse_estimate(self):
        msg = nse_estimate(10,2)
        self.assertEqual(msg[0], 0)
        self.assertEqual(msg[1], 12)  # Size = 4 bytes
        self.assertEqual(msg[2], 2)   # Query = 521 = 0x209
        self.assertEqual(msg[3], 9)   # 0x09 = 9
        self.assertEqual(msg[4], 0)   # Est = 0x000a
        self.assertEqual(msg[5], 0)   # 0x00
        self.assertEqual(msg[6], 0)   # 0x00
        self.assertEqual(msg[7], 10)  # 0x0a
        self.assertEqual(msg[8], 0)   # Dev = 0x0002
        self.assertEqual(msg[9], 0)   # 0x00
        self.assertEqual(msg[10], 0)  # 0x00
        self.assertEqual(msg[11], 2)  # 0x02

    def test_validate_query(self):
        msg = nse_query()
        self.assertTrue(validate_query(msg))

    def test_validate_query_wrong_size(self):
        size = 5
        query = 520
        msg = struct.pack('!2H',size, query)
        self.assertFalse(validate_query(msg))

    def test_validate_query_wrong_query_id(self):
        size = 5
        query = 521
        msg = struct.pack('!2H',size, query)
        self.assertFalse(validate_query(msg))

    def test_validate_estimate(self):
        msg = nse_estimate(10,2)
        self.assertTrue(validate_estimate(msg))

    def test_validate_estimate_wrong_size(self):
        size = 11
        estimate = 521
        est_peers = 10
        est_dev = 2
        msg = struct.pack('!2H2I',size, estimate, est_peers, est_dev)
        self.assertFalse(validate_estimate(msg))

    def test_validate_estimate_wrong_id(self):
        size = 12
        estimate = 522
        est_peers = 10
        est_dev = 2
        msg = struct.pack('!2H2I',size, estimate, est_peers, est_dev)
        self.assertFalse(validate_estimate(msg))




if __name__ == '__main__':
    unittest.main()
