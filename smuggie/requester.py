#/usr/bin/env python3
# Author: Aaron Esau <python@aaronesau.com>
#
# This module allows us to send pure HTTP(S) without the the request module's
# high-level implementation of HTTP.

from smartbytes import *
from pwn import *
from threading import Thread

import time


context.log_level = 'error'


class Request:
    def __init__(self, worker, request):
        self.worker = worker
        # cleanup potential CRLF issues
        # XXX: move this to before generating the payloads so that we can use
        #   LF without CR in some potential exploits
        self.request = smartbytes(request)

    def _cleanup(self):
        self.request = request.replace('\r', '').replace('\n', '\r\n')

    def _execute(self):
        self.error = False

        try:
            self.host, self.port = self.worker.host, self.worker.port
            self.socket = remote(self.host, self.port, **self.worker.config)

            self.socket.write(bytes(self.request))
            self.response = smartbytes(self.socket.recvall())

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
                raw_request = self._queue.pop(0)
            except IndexError:
                # done with all requests!
                break

            request = Request(self, raw_request)
            self._handle(request._execute())


class RequestEngine:
    def __init__(self, max_workers = 5, config = dict(), handlers = list()):
        self.max_workers = max_workers
        self.config = config
        self._handlers = [self._handle] + handlers

        # internal
        self._workers = list()
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

    def queue(self, host, port = None, handlers = list()):
        assert not self._started

        port = port or (443 if host.startswith('http:') else 80)
