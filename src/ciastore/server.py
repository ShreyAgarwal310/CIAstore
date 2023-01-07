#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Server - Caught In the Act Server

"Caught In the Act Server"


__title__ = 'Caught In the Act Server'
__author__ = 'CSHS Members'
__version__ = '0.0.0'


from typing import Final
from os import path
import sys
import socket
from pathlib import Path
from urllib.parse import urlencode
import time

import trio
from hypercorn.config import Config
from hypercorn.trio import serve
from quart_trio import QuartTrio
from quart import request, Response
from werkzeug import Response as wkresp

from . import htmlgen


def log(message: str, level: int = 0, log_dir: str | None = None) -> None:
    "Log a message to console and log file."
    levels = ['INFO', 'ERROR']

    if log_dir is None:
        log_dir = path.split(__file__)[0]
    log_file = path.join(log_dir, 'log.txt')

    log_level = levels[min(max(0, level), len(levels)-1)]
    log_time = time.asctime()
    log_message_text = message.encode("unicode_escape").decode("utf-8")

    log_msg = f'[{__title__}] [{log_time}] [{log_level}] {log_message_text}'

    if not path.exists(log_file):
        with open(log_file, mode='w', encoding='utf-8') as file:
            file.close()
        log('Log file does not exist!', 1)
        log('Created log file')
    with open(log_file, mode='a', encoding='utf-8') as file:
        file.write(f'{log_msg}\n')
        file.close()
    print(log_msg)


def find_ip() -> str:
    "Utility function to guess the IP where the server can be found from the network"
    # we get a UDP-socket for the TEST-networks reserved by IANA.
    # It is highly unlikely, that there is special routing used
    # for these networks, hence the socket later should give us
    # the IP address of the default route.
    # We're doing multiple tests, to guard against the computer being
    # part of a test installation.

    candidates: list[str] = []
    for test_ip in ('192.0.2.0', '198.51.100.0', '203.0.113.0'):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((test_ip, 80))
        ip_addr: str = sock.getsockname()[0]
        sock.close()
        if ip_addr in candidates:
            return ip_addr
        candidates.append(ip_addr)

    return candidates[0]


app: Final = QuartTrio(__name__)


@app.get('/')
async def root_GET() -> str:
    "Main page GET request"
    message = "If you're reading this, the web server was installed correctly.™"
    value = htmlgen.wrap_tag('i', message, False)
    html = htmlgen.contain_in_box('', value)
    return htmlgen.get_template('CompanyName.website', html)


async def run_async(root_dir: str,
                    port: int,
                    ip_addr: str | None = None) -> None:
    """Asynchronous Entry Point"""
    if ip_addr is None:
        ip_addr = find_ip()

    try:
        # Add more information about the address
        location = f'{ip_addr}:{port}'

        config = {
            'bind': location,
            'worker_class': 'trio',
            'errorlog': path.join(root_dir, 'log.txt'),
        }
        app.static_folder = Path(root_dir)

        config_obj = Config.from_mapping(config)

        print(f'Serving on http://{location}\n(CTRL + C to quit)')

        await serve(app, config_obj)
    except socket.error:
        log(f"Cannot bind to IP address '{ip_addr}' port {port}", 1)
        sys.exit(1)
    except KeyboardInterrupt:
        pass


def run() -> None:
    """Synchronous Entry Point"""
    root_dir = path.split(__file__)[0]
    port = 6002

    trio.run(run_async, root_dir, port)


if __name__ == '__main__':
    print(f'{__title__}\nProgrammed by {__author__}.\n')
    run()
