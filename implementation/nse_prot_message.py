from Crypto.Hash import SHA256
from datetime import datetime
from asym_crypto import *
import json
import base64
import pow
import math


'''
    This object is instantiated in main.py and holds all required variables
    for the nse protocol at runtime.
    It consists of functions to create, validate and update nse protocol messages
    and calculates the estimated peer count and standard deviation.
    It also serves as shared object for the api server which answers to nse queries
    from other local modules.
'''
class NSEHandler:
    def __init__(self, hostkey_path, pow_num_bits):
        self.msg = {}
        self.future_msg = {}
        self.msg_history = []
        self.hostkey_path = hostkey_path
        self.public_key_string = get_pubkey_string(hostkey_path)
        self.id = create_id(self.public_key_string)
        self.pow_num_bits = int(pow_num_bits)
        self.round = datetime.utcnow().strftime("%Y-%m-%d %H:00:00")
        self.proximity = 0
        self.est_peer_count = 0
        self.est_std_deviation = 0
        self.history_length = 15
        self.max_hop_count = 15
        self.PoW = dict()
        self.create_round_msg()


    # Update round msg, estimation and deviation in dependence to own id and future messages
    def create_round_msg(self):
        id = self.id
        time_hash = create_time_stamp_hash()
        self.round = datetime.utcnow().strftime("%Y-%m-%d %H:00:00")
        proximity = compare_binary_digest(time_hash, id)

        if self.future_msg:
            if self.future_msg["Round"] == self.round:
                if int(self.future_msg["Proximity"]) > proximity:
                    self.proximity = int(self.future_msg["Proximity"])
                else:
                    self.proximity = proximity
            else:
                self.proximity = proximity
        else:
            self.proximity = proximity

        self.future_msg = {}
        self.est_peer_count = self.calc_estimation(self.proximity)
        self.est_std_deviation = self.create_std_deviation()

        json_msg = self.create_msg(self.max_hop_count, self.round, self.proximity)
        self.PoW = json_msg["PoW"]
        json_msg_str = json.dumps(json_msg)
        self.msg = json_msg_str

    # Function to calculate the standard deviation of peer estimate
    def create_std_deviation(self):

        # Create list of proximities
        proximities = list(map(lambda d: d['Proximity'], self.msg_history))
        proximities.append(self.proximity)

        # Build list of estimated peers
        estimates = list(map(lambda d: self.calc_estimation(int(d)), proximities))

        # Calculate sum mean and number of values of the list
        est_sum = sum(estimates)
        est_amount = len(estimates)
        est_mean = est_sum/est_amount
        quadratic_values = list(map(lambda d: (d-est_mean)**2, estimates))

        # Calculate the standard deviation. If msg history is empty the deviation is zero
        std_dev=0
        if est_amount>1:
            std_dev = math.sqrt((1/(est_amount-1))*(sum(quadratic_values)))
        return std_dev

    # Function to create message as a dict
    def create_msg(self, hop_count, round, proximity):
        PoW = pow.createPoW(int(self.pow_num_bits))
        msg = str(hop_count) + str(round) + str(proximity) + str(self.public_key_string) + json.dumps(PoW)
        sign = create_sign(msg, self.hostkey_path)
        msg_dict = {"Hop-Count": str(hop_count), "Round": str(round), "Proximity": str(proximity), "Pub-key" : str(self.public_key_string), "PoW": PoW, "Sign": str(base64.b64encode(sign))}
        return msg_dict

    # Function to append history messages
    def append_msg_to_history(self):
        if len(self.msg_history) >= self.history_length:
            self.msg_history = self.msg_history[1:]
        self.msg_history.append(json.loads(self.msg))

    # Function to calculate the network site estimate
    def calc_estimation(self, proximity):
        return round(2.0**(proximity-0.332747))

    # This function compares a given message with the current messages of the object
    def update_msg(self, new_msg, freq):
        try:
            own_dict = json.loads(self.msg)
            new_dict = json.loads(new_msg)
        except:
            print("Protocol message not valid!")
            return False

        own_proximity_int = int(own_dict["Proximity"])
        new_proximity_int = int(new_dict["Proximity"])
        own_round = own_dict["Round"]
        new_round = new_dict["Round"]
        format = '%Y-%m-%d %H:%M:%S'
        own_time = datetime.strptime(own_round, format)
        new_time = datetime.strptime(new_round, format)

        delta_seconds = (own_time - new_time).total_seconds()
        delta_rounds = int(delta_seconds / freq)

        # New message is one round behind ours
        if delta_rounds == 1:
            # Check if history is empty
            if len(self.msg_history) == 0:
                last_round_prox = -1
            else:
                try:
                    last_round_prox = int(self.msg_history[-1]["Proximity"])
                except:
                    raise Exception("Proximity does not contain an int")

            if last_round_prox < new_proximity_int:
                # Decrement hop-count if > 0
                hop_count_recieved = int(new_dict["Hop-Count"])
                hop_count = max(hop_count_recieved-1, 0)
                json_msg = self.create_msg(hop_count, new_time, new_proximity_int)

                if len(self.msg_history) == 0:
                    self.msg_history.append(json_msg)
                else:
                    self.msg_history[-1]=json_msg

                # Calculate new standard deviation
                self.est_std_deviation = self.create_std_deviation()

                # If hop-count == 1 do not forward last round msg
                if hop_count_recieved == 1:
                    return False
                else:
                    return True
            else:
                return False

        # New msg is one round before ours
        elif delta_rounds == -1:
            if (len(self.future_msg) == 0 or int(self.future_msg["Proximity"]) < new_proximity_int):
                # Update current future message
                hop_count = max(int(new_dict["Hop-Count"])-1,0)
                json_msg = self.create_msg(hop_count, new_time, new_proximity_int)
                self.future_msg = json_msg
                return False

        # New msg is same round
        elif delta_rounds == 0:
            if own_proximity_int < new_proximity_int:
                print("Recieved message with higher proximity. Own:" + str(own_proximity_int) + " Received: " + str(new_proximity_int))

                # Decrement hop-count if > 0
                hop_count_recieved = int(new_dict["Hop-Count"])
                hop_count = max(hop_count_recieved-1, 0)
                json_msg = self.create_msg(hop_count, new_time, new_proximity_int)
                self.proximity = new_proximity_int
                self.est_peer_count = self.calc_estimation(self.proximity)

                # Calculate new std_deviation
                self.est_std_deviation = self.create_std_deviation()

                json_msg = self.create_msg(hop_count, self.round, self.proximity)
                self.PoW = json_msg["PoW"]
                json_msg = json.dumps(json_msg)
                self.msg = json_msg
                print("Updated own round msg!")

                # If hop-count == 1 do not forward last round msg
                if hop_count_recieved == 1:
                    return False
                else:
                    return True
            else:
                print("Recieved message with lower or equal proximity. Own:" + str(own_proximity_int) + " Received: " + str(new_proximity_int))
                return False

        # New msg is more than one round before or behind, no forwarding
        else:
            print("Msg older or newer than one round!")
            return False

    # This function validates a given protocol message
    def validate_msg(self, msg):
        # Check correct json format
        try:
            dict = json.loads(msg.decode('utf8'))
        except json.decoder.JSONDecodeError:
            print("Protocol message not valid!")
            return False
        if not isinstance(dict["Hop-Count"], str):
            print("Invalid Type of Hop-Count")
            return False
        if not isinstance(dict["Round"], str):
            print("Invalid Type of Round")
            return False
        if not isinstance(dict["Proximity"], str):
            print("Invalid Type of Proximity")
            return False
        if not isinstance(dict["Pub-key"], str):
            print("Invalid Type of Public Key")
            return False
        if not type(dict["PoW"]) == type({}):
            print("Invalid Type of PoW")
            return False
        if not isinstance(dict["PoW"]["Time"], str):
            print("Invalid Type of Time in PoW")
            return False
        if not isinstance(dict["PoW"]["Random-number"], str):
            print("Invalid Type of Random-Number in PoW")
            return False
        if not isinstance(dict["PoW"]["Hash"], str):
            print("Invalid Type of Hash in PoW")
            return False
        if not isinstance(dict["Sign"], str):
            print("Invalid Type of Signature")
            return False

        # Check correct hop-count
        hop_count = int(dict["Hop-Count"])
        if hop_count not in range(0,16):
            print("Hop-Count out of range!")
            return False

        # Check correct round format
        try:
            round = dict["Round"]
            format = '%Y-%m-%d %H:%M:%S'
            round = datetime.strptime(round, format)
        except:
            print("Round not in correct format!")
            return False

        # Check correct proximity format
        proximity = int(dict["Proximity"])
        if proximity not in range(0,257):
            print("Proximity out of range!")
            return False

        # Extract sign and pub-key from message
        sign = base64.b64decode(dict["Sign"][2:-1])
        pub_key = dict["Pub-key"][2:-1].replace(r"\n","\n")
        PoW = {"Time": dict["PoW"]["Time"], "Random-number": dict["PoW"]["Random-number"], "Hash": dict["PoW"]["Hash"]}

        # Check if claimed proximity is ok for given id and round-time when not forwarded msg
        if hop_count == self.max_hop_count:
            id = create_id(pub_key.encode('utf-8'))
            hashed = SHA256.new()
            round_time = dict["Round"]
            print(round_time)
            hashed.update(round_time.encode('utf-8'))
            if proximity != compare_binary_digest(hashed.hexdigest(), id):
                print("Proximity not valid!")
                return False

        msg_string = dict["Hop-Count"] + dict["Round"] + dict["Proximity"] + dict["Pub-key"] + json.dumps(PoW)

        # Check if sign and pow is correct
        valid_sign = validate_sign(sign, msg_string, pub_key)
        valid_pow = pow.validatePoW(self.round, round, PoW, self.pow_num_bits)

        if not valid_sign:
            print("Signature not validable!")
            return False
        if not valid_pow:
            print("PoW not valid!")
            return False

        return True
