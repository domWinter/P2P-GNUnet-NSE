import asyncio
import api_message

'''
    This module contains the api server object, which is created in main.
    The server binds to the specified local port and waits for async requests.
    If a request is recognized and valid, a nse estimate is send as answer.
'''

class APIServer:
    def __init__(self, port, handler):
        self.server = None
        self.port = port
        self.handler = handler

    # Function to await and handle incoming requests
    async def _handle_api_request(self, reader, writer):
        data = await reader.read(8)
        addr = writer.get_extra_info('peername')
        print("\nRecieved API NSE query from " + str(addr))

        if api_message.validate_query(data):
            print(" NSE query is valid, sending estimation!")
            nse_estimate = api_message.nse_estimate(self.handler.est_peer_count, self.handler.est_std_deviation)
            writer.write(nse_estimate)
            await writer.drain()
            writer.close()
        else:
            print(" NSE Query not valid, closing the connection!")
            writer.close()

    # Function to start the server
    def start(self, loop):
        print("\nStarted API Server on Port " + self.port+"!")
        coro = asyncio.start_server(self._handle_api_request, '127.0.0.1', self.port, loop=loop)
        self.server = loop.run_until_complete(coro)

    # Function to close the server
    def stop(self, loop):
        if self.server is not None:
            self.server.close()
            loop.run_until_complete(self.server.wait_closed())
            self.server = None
