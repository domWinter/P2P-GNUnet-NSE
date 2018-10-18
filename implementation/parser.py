import configparser

'''
    This module parses a given ini configuration file with help of the
    configparser library and saves all values as object attributes.
'''

class GossipParser:
    def __init__(self, file):
        self.gossip_cache_size=""
        self.gossip_max_connections=""
        self.gossip_bootstrapper_address=""
        self.gossip_bootstrapper_port=""
        self.gossip_listen_port=""
        self.gossip_listen_address=""
        self.gossip_api_address=""
        self.gossip_api_port=""

        self.nse_listen_address=""
        self.nse_listen_port=""
        self.nse_api_address=""
        self.nse_api_port=""
        self.nse_mockup_estimate_max=""
        self.nse_mockup_deviation_max=""
        self.nse_pow_num_bits=""
        self.parse(file)

    def parse(self,file):

        try:
            config = configparser.ConfigParser()
            config.read(file)

            # Gossip related variables
            self.gossip_cache_size = config.get("gossip", "cache_size")
            self.gossip_max_connections = config.get("gossip", "max_connections")
            self.gossip_bootstrapper_address = config.get("gossip", "bootstrapper").split(':')[0]
            self.gossip_bootstrapper_port = config.get("gossip", "bootstrapper").split(':')[1]
            self.gossip_listen_address = config.get("gossip", "listen_address").split(':')[0]
            self.gossip_listen_port = config.get("gossip", "listen_address").split(':')[1]
            self.gossip_api_address = config.get("gossip", "api_address").split(':')[0]
            self.gossip_api_port = config.get("gossip", "api_address").split(':')[1]

            # NSE related variables
            self.nse_listen_address = config.get("nse", "listen_address").split(':')[0]
            self.nse_listen_port = config.get("nse", "listen_address").split(':')[1]
            self.nse_api_address = config.get("nse", "api_address").split(':')[0]
            self.nse_api_port = config.get("nse", "api_address").split(':')[1]
            self.nse_mockup_estimate_max = config.get("nse", "mockup_estimate_max")
            self.nse_mockup_deviation_max = config.get("nse", "mockup_deviation_max")
            self.nse_pow_num_bits = config.get("nse", "pow_num_bits")

        # Exception Handling
        except IOError:
    	    raise Exception("IOError, check config and retry!")
        except configparser.NoSectionError:
            raise Exception("Failed to parse config ini, check path!")
        except configparser.NoOptionError:
            raise Exception("Parsed config does not contain all needed values!")
        except:
            raise Exception("Something went wrong during parsing, check config and retry!")
