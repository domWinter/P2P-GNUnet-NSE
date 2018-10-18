import os,sys,inspect
import socket

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir)

import api_message


def main():
    query = api_message.nse_query()
    print('Sending query: ',query)
    print('')

    host = "127.0.0.1"
    port = 5001
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(query)
    data = s.recv(1024)
    s.close()
    print('Received estimate: ', repr(data))
    print(' --> Length:', data[1])
    print(' --> Estimate_ID: 0x', data[2], 0, data[3])
    print(' --> Estimated_peers: 0x', data[4], data[5], data[6], data[7])
    print(' --> Std_deviation: 0x', data[8], data[9], data[10], data[11])

if __name__ == "__main__":
    main()
