'''
The server class

Handles serving the HTML and talking websockets
'''

from typing import Any, Dict

import asyncio
import json
import os
import websockets

from http.server import HTTPServer, SimpleHTTPRequestHandler
from threading import Thread

from .util_funcs import log_info, log_error


class AriadneHTTPHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        # Uncomment to see resources being requested
        #log_info(format % args, 'ARIADNE:HTTP')
        pass


def run_http_server(address: str, port: int):
    handler = AriadneHTTPHandler
    current_dir = os.path.dirname(os.path.abspath(__file__))
    web_dir = os.path.join(current_dir, '..', 'web')
    os.chdir(web_dir)
    with HTTPServer((address, port), handler) as httpd:
        log_info(f'Serving web UI at http://{address}/{port}', 'ARIADNE:HTTP')
        httpd.serve_forever()


json_contents = None

async def websocket_handler(websocket, path):
    global json_contents
    log_info('Websocket Client connected', 'ARIADNE:WS')
    # Wait until graph JSON is available
    while json_contents is None:
        await asyncio.sleep(0.1)

    log_info(f'JSON loaded: {len(json_contents)} bytes', 'ARIADNE:WS')
    # FUTURE: switch from polling model to async
    prev_json = None
    try:
        while True:
            await websocket.send(json_contents)
            # Uncomment to see size of each JSON update being sent out
            #log_info(f'JSON sent, {len(json_contents)} bytes', 'ARIADNE:WS')
            prev_json = json_contents
            while prev_json == json_contents:
                await asyncio.sleep(0.1)
    except websockets.exceptions.ConnectionClosedError as e:
        log_info(f'Client connection closed with code {e.code}', 'ARIADNE:WS')


class AriadneServer():
    def __init__(self, ip: str, http_port: int, websocket_port: int):
        self.ip = ip
        self.http_port = http_port
        self.websocket_port = websocket_port

    def start_webserver(self):
        self.http_thread = Thread(
            target=run_http_server,
            args=(self.ip, self.http_port),
            daemon=True,
        )
        self.http_thread.start()

    def start_websocket_server(self):
        self.websocket_thread = Thread(
            target=self.run_websocket_server,
            args=tuple(),
            daemon=True,
        )
        self.websocket_thread.start()

    def set_graph_data(self, json_obj: Dict[str, Any], title: str):
        global json_contents
        json_obj['title'] = title
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
