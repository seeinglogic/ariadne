'''
The server class

Handles serving the HTML and talking websockets
'''

from typing import Any, Dict

import asyncio
import json
import os
from pathlib import Path
import websockets

from http.server import HTTPServer, SimpleHTTPRequestHandler
from threading import Thread

from .util_funcs import log_info, log_error, get_web_dir, short_name


# Ports are per-Binary Ninja instance (which has its own Python interpreter)
instance_http_port: int = -1
instance_websocket_port: int = -1
server_instance = None


class AriadneHTTPHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        """Serve a GET request (with specific fix for JS)."""
        path = Path(self.translate_path(self.path))

        # For nonstandard websocket ports, fix it in the JS on the fly
        if instance_websocket_port != 7890 and path.parent.name == 'web' and path.name == 'main.js':
            with open(path) as js_file:
                js_contents = js_file.read()
                js_contents = js_contents.replace('server_port = 7890', f'server_port = {instance_websocket_port}')

            # Write the contents to a new file, then change the path to match it
            new_name = f'{path.stem}-{instance_websocket_port}{path.suffix}'
            new_file = path.with_name(new_name)
            with open(new_file, 'w') as nf:
                nf.write(js_contents)

            # self.path is relative to web/ as the root
            override_path = f'/{new_file.name}'
            self.path = str(override_path)

        super().do_GET()

    def log_message(self, format: str, *args: Any) -> None:
        # Uncomment to see resources being requested
        #log_info(format % args, 'ARIADNE:HTTP')
        pass


def run_http_server(address: str, port: int):
    handler = AriadneHTTPHandler
    os.chdir(get_web_dir())
    with HTTPServer((address, port), handler) as httpd:
        log_info(f'Serving web UI at http://{address}:{port}', 'ARIADNE:HTTP')
        httpd.serve_forever()


# The two global strings for websocket send/recv
json_contents = None
client_msg = None


async def read_client(websocket):
    global client_msg
    # This will time out if the client doesn't send any messages
    client_msg = await websocket.recv()


async def websocket_handler(websocket, path):
    global json_contents, client_msg
    log_info('Websocket Client connected', 'ARIADNE:WS')
    # Wait until graph JSON is available
    while json_contents is None:
        await asyncio.sleep(0.1)

    # FUTURE: switch from polling model to async
    prev_json = None
    try:
        while True:
            # Tell the core to graph a new function
            if client_msg:
                try:
                    client_dict = json.loads(client_msg)
                    bv_name = client_dict['bv']
                    start_addr = client_dict['start']
                    server_instance.core.graph_new_neighborhood(bv_name, start_addr)
                except Exception as e:
                    log_error(f'websocket_handler: client_msg handling exception: "{e}"')
                    # the JSON object must be str, bytes or bytearray not coroutine
                client_msg = None

            # Send the new graph data to the web UI
            if prev_json != json_contents:
                await websocket.send(json_contents)
                # Uncomment to see size of each JSON update being sent out
                #log_info(f'JSON sent, {len(json_contents)} bytes', 'ARIADNE:WS')
                prev_json = json_contents

            # Either the core will set json_contents or read_client will set client_msg
            while prev_json == json_contents and client_msg is None:
                try:
                    await asyncio.wait_for(read_client(websocket), timeout=0.1)
                except asyncio.exceptions.TimeoutError:
                    pass
                await asyncio.sleep(0)
    except websockets.exceptions.ConnectionClosedError as e:
        log_info(f'Client connection closed with code {e.code}', 'ARIADNE:WS')


class AriadneServer():
    def __init__(self, core, ip: str, http_port: int, websocket_port: int):
        self.core = core  # AriadneCore
        self.ip = ip
        self.http_port = http_port
        self.websocket_port = websocket_port

    def start_webserver(self):
        global instance_http_port
        instance_http_port = self.http_port
        self.http_thread = Thread(
            target=run_http_server,
            args=(self.ip, self.http_port),
            daemon=True,
        )
        self.http_thread.start()

    def start_websocket_server(self):
        global instance_websocket_port, server_instance
        instance_websocket_port = self.websocket_port
        server_instance = self

        self.websocket_thread = Thread(
            target=self.run_websocket_server,
            args=tuple(),
            daemon=True,
        )
        self.websocket_thread.start()

    def set_graph_data(self, bv, json_obj: Dict[str, Any], title: str):
        global json_contents
        json_obj['title'] = title
        json_obj['bv'] = short_name(bv)
        json_str = json.dumps(json_obj)
        json_contents = json_str

    def run_websocket_server(self):
        try:
            event_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(event_loop)
            start_server = websockets.serve(websocket_handler, self.ip, self.websocket_port)
            #log_info(f'Websocket listening on {self.ip}:{self.websocket_port}...', 'ARIADNE:WS')
            event_loop.run_until_complete(start_server)
            event_loop.run_forever()
        except Exception as e:
            log_error(f'Caught Exception: {e}', 'ARIADNE:WS')
            log_error(f'Websocket server stopping...', 'ARIADNE:WS')
