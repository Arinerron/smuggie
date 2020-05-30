#/usr/bin/env python3
# Author: Aaron Esau <python@aaronesau.com>
#
# This module allows us to send pure HTTP(S) without the the request module's
# high-level implementation of HTTP.

from .logger import *

from smartbytes import *
from pwn import *
from threading import Thread
from http.client import parse_headers

import io
import time


context.log_level = 'error'


class Request:
    def __init__(self, request, host = None, port = None, config = dict()):
        self.request = self._cleanup(smartbytes(request))

        self.headers = {
            key : val
            for key, val in
            parse_headers(BytesIO(bytes(self.request))).items()
        }

        self.host = host or request.headers['Host']
        self.port = port or (443 if host.startswith('http:') else 80)
        self.config = config

    def _cleanup(self):
        # cleanup potential CRLF issues
        # XXX: move this to before generating the payloads so that we can use
        #   LF without CR in some potential exploits
        return self.request.replace('\r', '').replace('\n', '\r\n')

    def _execute(self, worker):
        self.error = False

        try:
            time_pre_connect = time.time()
            self.socket = remote(self.host, self.port, {
                **worker.config,
                **self.config
            })
            self.time_connect = time.time() - time_pre_connect

            self.socket.write(bytes(self.request))

            time_pre_response = time.time()
            self.response = smartbytes(self.socket.recvall())
            self.time_response = time.time() - time_pre_response

            try:
                self.socket.close()
            except Exception:
                # XXX: what's the IOError exception called again
                pass
        except Exception as e:
            self.error = e

        return self


class RequestWorker(Thread):
    def __init__(self, engine, host, port, handlers = list(), config = dict()):
        self.engine = engine
        self.host = host.strip()
        self.port = port
        self._handlers = handlers
        self.config = {**{
            'tls' : (True if self.port == 443 else False),
            'timeout' : 5,
            'level' : 'error'
        }, **config}

        # internal
        self._queue = list()

    def queue(self, request):
        self._queue.append(request)

    def _handle(self, request):
        for handler in self._handlers:
            if handler(request) == False:
                return False

        return True

    def run(self):
        while True:
            try:
                request = self._queue.pop(0)

                assert request.host == self.host
                assert request.port == self.port
            except IndexError:
                # done with all requests!
                break
            except AssertionError:
                log.error(f'Skipping request due to host or port mismatch (request {request.host}:{request.port} != worker {self.host}:{self.port})')
                continue



            self._handle(request._execute(self))


'''
XXX: deprecated
'''
'''
class RequestEngine:
    def __init__(self, max_workers = 5, config = dict(), handlers = list()):
        self.max_workers = max_workers
        self.config = config
        self._handlers = [self._handle] + handlers

        # internal
        self._workers = set()
        self._workers_cache = list()
        self._started = False

    def _handle(self, request):
        assert self._started

        return True

    def _get_worker(self, host, port):
        assert not self._started

        for worker in self._workers_cache:
            if host == worker.host and port == worker.port:
                return worker

        worker = RequestWorker(self, host, port, handlers = self._handlers, config = self.config)
        self._workers_cache.append(worker)
        return worker

    def queue(self, request):
        assert not self._started

        worker = self._get_worker(request.host, request.port)
        self.workers.add(worker)
        worker.queue(request)

        return worker

    def start(self, block = True):
        assert not self._started
        self._started = True

        for worker in self._workers:
            worker.start()

        if block:
            self.join()

    def join(self):
        assert self._started

        for worker in self._workers:
            worker.join()
'''
