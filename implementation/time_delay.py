import math
import random

'''
This function creates a delay for the main broadcast messages
which were created by the own peer.
The delay depends on the frequency of the rounds and the
proximity from the last round which is given by the msg history.
A good proximity in comparison to the last round yields
to a small delay while a bad estimate gives a long one.
'''
def create_flood_delay(msg_history, cur_prox, freq):
    # Get the proximity of the last round if there is one.
    if len(msg_history) == 0:
        prev_prox = 0
    else:
        prev_prox = int(msg_history[-1]["Proximity"])
    # Use the variables to compute the delay
    delay = (freq / 2.0) - ((freq/math.pi) * math.atan(cur_prox - prev_prox))
    return delay

'''
This function creates a delay for the broadcast messages which are
received from the other peers. Thereby the messages will be forwarded if they
include a better proximity. The processing delay is calculated with previous
proximity, the current proximity, the frequency of the round and the
network_diameter. Thereby the network_diameter is the maximum of the
hopcounts of last 15 rounds.
The delay is randomly chosen between two delays of the
respective consecutive proximities.
'''
def create_processing_delay(msg_history, proximity, freq, max_hop_count):
    network_diameter = 15
    for dict in msg_history:
        if network_diameter > int(dict.get("Hop-Count")):
            network_diameter = int(dict.get("Hop-Count"))
    network_diameter = max_hop_count + 1 - network_diameter
    cur_prox = proximity

    # Calculate first delay
    delay1 = create_flood_delay(msg_history, cur_prox - 1, freq)

    # Calculate second delay
    delay2 = create_flood_delay(msg_history, cur_prox, freq)

    # Create upper bound of the processing delay and choose it randomly
    delay_range_upper_bound= (delay1 - delay2) / network_diameter
    delay = random.uniform(0, delay_range_upper_bound)
    return delay
