from parser import GossipParser
from hashlib import sha256
from api_server import APIServer
from nse_prot_message import NSEHandler
from datetime import datetime, timedelta
from time_delay import create_flood_delay, create_processing_delay
import asyncio
import gossip
import os
import json
import argparse

dir = os.path.dirname(os.path.realpath(__file__))

'''
    This is the main programm that controls all defined loops and asyncio
    events. It consists of all parameters parsed in the first step and has
    different functions to listen and respond to the gossip module.
    Moreover, this program binds to the specified api server port and listens
    for incoming nse queries from other local modules on this port.
'''
def main():

    print("\n############ NSE Module of Group 37 #############\n")

    # Parse arguments from command line
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--config", default= dir + '/' + 'config.ini',
            help="Config file")
    ap.add_argument("-k", "--hostkey", default=dir + '/' + 'hostkey.pem',
            help="Hostkey file")
    args = vars(ap.parse_args())

    # As first step parse the ini configuration file
    config = GossipParser(args["config"])
    hostkey = args["hostkey"]

    print("Configuration parsed with success!")


    # Create handler object with path to hostkey and pow_num_bits from config
    try:
        print("Setup peer ID from public key")
        handler = NSEHandler(hostkey, config.nse_pow_num_bits)
    except:
        raise Exception("Could not create NSEHandler, check path to Hostkey!")


    '''
        This function is the main protocol handler and gets invoked by main.
        It handles all further protocol loops and tasks.
    '''
    def protocol_handler():
        # Message Types
        gossip_notification = 502
        nse_query_dtype = 520
        nse_estimate_dtype = 521
        nse_msg_dtype = 530
        # Frequency (1h)
        freq = 3600

        # Function to forward recieved round messages or history messages
        def forward(delay, current_round_msg):
            try:
                # Forward round msg if not altered (hash check) during delay
                if current_round_msg:
                    current_msg_hash = sha256(handler.msg.encode('UTF-8')).hexdigest()
                    yield from asyncio.sleep(delay)
                    updated_msg_hash = sha256(handler.msg.encode('UTF-8')).hexdigest()
                    if current_msg_hash == updated_msg_hash:
                        announce = gossip.announce(1, nse_msg_dtype, handler.msg)
                        writer.write(announce)

                # Forward history msg if not altered (hash check) during delay
                else:
                    current_msg_hash = sha256(json.dumps(handler.msg_history[-1]).encode('UTF-8')).hexdigest()
                    yield from asyncio.sleep(0.05)
                    updated_msg_hash = sha256(json.dumps(handler.msg_history[-1]).encode('UTF-8')).hexdigest()
                    if current_msg_hash == updated_msg_hash:
                        announce = gossip.announce(1, nse_msg_dtype, json.dumps(handler.msg_history[-1]))
                        writer.write(announce)
            except:
                raise Exception("Forwarding messages failed!")


        '''
            This function is the main broadcast loop which calculates a new
            proximity every new round.
            In dependence of the calculated proximity the loop delays it
            execution and only sends the first calculated estimate if no new
            round message with a better estimate arrived during delay.
        '''
        def broadcastloop():
            while True:
                try:
                    # Calculate time until next round and wait
                    now = datetime.now()
                    nexthour = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
                    delta = nexthour - now
                    deltaseconds = delta.total_seconds()
                    yield from asyncio.sleep(deltaseconds)

                    # New round started, append old best round message to history and create new round msg
                    handler.append_msg_to_history()
                    handler.create_round_msg()

                    # Calculate msg hash for later comparison
                    current_msg_hash = sha256(handler.msg.encode('UTF-8')).hexdigest()

                    # Calculate flood delay and wait until reached
                    startingdelay = create_flood_delay(handler.msg_history, handler.proximity, freq)
                    yield from asyncio.sleep(startingdelay)

                    # Calculate msg hash again to check if msg was updated while waiting
                    updated_msg_hash = sha256(handler.msg.encode('UTF-8')).hexdigest()

                    # If message still first round message announce it
                    if current_msg_hash == updated_msg_hash:
                        announce = gossip.announce(64, nse_msg_dtype, handler.msg)
                        writer.write(announce)
                    else:
                        print("NO ROUND-MSG ANNOUNCE")
                except:
                    raise Exception("Broadcasting round message failed!")

        '''
            This function is the notification loop which always waits for incoming
            gossip notifications and updates the peers estimate, history and future
            messages according to the recieved messages.
        '''
        def notification_loop():
            while True:
                yield from asyncio.sleep(0.5)
                print('\nWaiting for gossip notifications...')

                # Read Notification
                try:
                    size_in_bytes = yield from reader.read(2)
                    size = int.from_bytes(size_in_bytes, byteorder = "big")
                    data = yield from reader.read(size-2)

                    notification_in_bytes = data[:2]
                    notification = int.from_bytes(notification_in_bytes, byteorder = "big")

                    message_id_in_bytes = data[2:4]
                    message_id = int.from_bytes(message_id_in_bytes, byteorder = "big")

                except BrokenPipeError:
                    raise Exception("Lost connection to gossip module!")
                except:
                    raise Exception("Reading gossip notification failed!")

                print('\nRecieved message with ID: ' + str(message_id))

                # Validate notification and send validation message to gossip
                try:
                    if notification == gossip_notification:
                        msg = data[6:]
                        if handler.validate_msg(msg):
                            # Calculate msg hash again for later comparison
                            msg_hash = sha256(handler.msg.encode('UTF-8')).hexdigest()

                            # If new proximity better than own and new message has not altered (hash comparison) forward with delay
                            if handler.update_msg(msg, freq):
                                if msg_hash == sha256(handler.msg.encode('UTF-8')).hexdigest():
                                    current_round_msg = False
                                else:
                                    current_round_msg = True

                                # Calculate processing delay and forward
                                delay = create_processing_delay(handler.msg_history, handler.proximity, freq, handler.max_hop_count)
                                asyncio.ensure_future(forward(delay, current_round_msg))
                                writer.write(gossip.validation(message_id,True))
                            else:
                                writer.write(gossip.validation(message_id,False))
                        else:
                            writer.write(gossip.validation(message_id,False))
                    else:
                        writer.write(gossip.validation(message_id,False))
                except:
                    raise Exception("Processing notification message failed!")


        # Open connection to gossip
        print("\nOpening connection to gossip module on: " + str(config.gossip_api_address) + ":" + str(config.gossip_api_port) + '\n')
        try:
            reader, writer = yield from asyncio.streams.open_connection(config.gossip_api_address, config.gossip_api_port, loop=loop)
        except:
            print("Connecting to Gossip failed!")
            loop.stop()

        yield from asyncio.sleep(1)

        # First gossip announce
        try:
            announce = gossip.announce(64, nse_msg_dtype, handler.msg)
            writer.write(announce)
        except:
            raise Exception("Sending first gossip announce failed!")


        # Send gossip notify
        try:
            notify = gossip.notify(nse_msg_dtype)
            writer.write(notify)
        except:
            raise Exception("Sending gossip notify failed!")

        # Start asynchronous loops
        asyncio.ensure_future(broadcastloop())
        yield from notification_loop()
        writer.close()


    # Create main event loop
    loop = asyncio.get_event_loop()

    try:
        # Bind api server on specified port from config ini
        api_server = APIServer(config.nse_api_port, handler)
        api_server.start(loop)
        asyncio.ensure_future(protocol_handler())

        loop.run_forever()

    except KeyboardInterrupt as keyboard_interrupt:
        print("\nInterrupted by keyboard!")
        pass

    finally:
        api_server.stop(loop)
        tasks = asyncio.Task.all_tasks(loop)
        for task in tasks:
            task.cancel()
        loop.run_until_complete(asyncio.sleep(0))
        loop.stop()






if __name__ == "__main__":
    main()
