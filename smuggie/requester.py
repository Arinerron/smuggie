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
import collections


context.log_level = 'error'

'''
Parse out headers to OrdereDict({key => val})

XXX: hacky parsing that doesn't conform to RFC, TODO...
NOTE: DO NOT reuse this code in your projects as this code itself could enable
  request smuggling attacks!
'''
def parse_header(raw_request):
    headers = raw_request.split('\r\n\r\n', 1)[0].strip().split('\r\n')
    headers.pop(0) # remove the first line (GET / HTTP/1.1)

    output_dict = collections.OrderedDict()

    for header in headers:
        key, value = header.strip().split(': ', 1)

        # XXX: find a better case insensitive solution
        key = key.lower()
        assert key not in output_dict

        output_dict[key] = values

    return output_dict


class Request:
    def __init__(self, raw_request, host = None, port = None, request_config = dict()):
        self.raw_request = self._cleanup(smartbytes(raw_request))

        self.headers = parse_header(self.raw_request)

        self.host = host or self.headers['host']
        self.port = port or (443 if host.startswith('http:') else 80)

        assert self.host
        assert self.port

        self.request_config = {
            # prioritize Request's config over the RequestWorker's
            **worker.request_config,
            **request_config
        }

    def _cleanup(self):
        # cleanup potential CRLF issues
        # XXX: move this to before generating the payloads so that we can use
        #   LF without CR in some potential exploits
        return self.raw_request.replace('\r', '').replace('\n', '\r\n')

    def _execute(self, worker):
        self.error = False

        try:
            time_pre_connect = time.time()
            self.socket = remote(self.host, self.port, self.request_config)
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
    def __init__(self, host, port, request_config = dict()):
        self.host = host.strip()
        self.port = port
        self.request_config = {**{
            'tls' : (True if self.port == 443 else False),
            'timeout' : 5,
            'level' : 'error'
        }, **request_config}

        # internal
        self._queue = list()

    def queue(self, request):
        self._queue.append(request)

    def run(self):
        self.results = list() # keep order

        # loop broken by .pop(0) IndexError
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

            result = request._execute(self)
            self.results.append(result)
