#/usr/bin/env python3
# Author: Aaron Esau <python@aaronesau.com>
#
# This module contains the logic to determine whether or not a given
# header configuration is exploitable or not.

from .filter import RISK_LEVEL_HIGH, RISK_LEVEL_MEDIUM, RISK_LEVEL_LOW, format_header
from .requester import RequestWorker, Request

import re


PHASE_TIME, PHASE_DIFFERENTIAL = 1, 2


'''
Takes in a request and tests it for smuggling
'''
class RequestScan(Thread):
    def __init__(self, raw_request, host = None, port = None, config = dict(), request_config = dict()):
        self.raw_request = str(raw_request.request) if isinstance(raw_request, Request) else raw_request
        self.host = host
        self.port = port

        # instantiate a temporary Request to parse host/port
        request = self._new_request()
        self.host = request.host
        self.port = request.port

        self.request_config = request_config # passed to Request objects. Autoconfigured in RequestWorker's __init__.
        self.config = { # config specific to scans
            'max_level' : RISK_LEVEL_LOW, # how in-depth/intense the scan should be
            'confidence' : None, # confidence interval. None => auto calculate based on risk level
            'tests_per_filter' : None, # number of baseline/tests
            **config
        }

        # automatically configure stuff based on what the user inputted
        self.config['confidence'] = self.config['confidence'] or {
            RISK_LEVEL_LOW : 0.8,
            RISK_LEVEL_MEDIUM : 0.75,
            RISK_LEVEL_HIGH: 0.7
        }[self.config['max_level']]

        self.config['tests_per_filter'] = self.config['tests_per_filter'] or {
            RISK_LEVEL_LOW : 10,
            RISK_LEVEL_MEDIUM : 15,
            RISK_LEVEL_HIGH: 20
        }[self.config['max_level']]

    '''
    Create a new Request object based on Scan settings
    '''
    def _new_request(self):
        return Request(self, self.raw_request, **self.request_config)

    '''
    Start scan. Blocks until done. Results are in self.results.
    '''
    def run(self):
        # TODO: test for more than just this
        patch_header = f'Transfer-Encoding: {self.raw_request.headers["transfer-encoding"]}'.lower()

        # XXX: only content-length?
        filters = format_header(
            patch_header, # XXX: case insensitive code is buggy, see parse_header in requester.py
            max_level = self.config['max_level']
        )

        self.results = {
            'phase1' : {
                'success' : False
            }
        }

        # phase 1 execution

        initial_results = self._run_phase1(filters, patch_header, PHASE_TIME)

        # phase 1 analysis

        initial_analysis = self.analyze(initial_results)

        log.info('Got P1 analysis: ' + str(initial_analysis))

    '''
    Phase 1 is time-based detection
    '''
    def _run_phase(self, filters, patch_header, phase):
        tests_per_filter = self.config['tests_per_filter']
        worker = RequestWorker(self.host, self.port, self.request_config)

        # queue baseline requests

        baseline_requests = [
            self._new_request()
            for _ in range(tests_per_filter)
        ]

        for request in baseline_requests:
            worker.queue(request)

        # queue test requests

        test_requests = list()

        for filter in filters:
            request = self.raw_request

            '''

            TODO:

            check what phase we are in and dynamically construct HTTP request depending on what phase.
            for example, add a long content length but no body to cause timeout if phase 1
            if phase 2, set short secondary content-length (yeah, smuggle a request...) and set a longer body

            '''

            # XXX: regex injection + shitty/buggy code
            remove_header = lambda raw_request, header : smartbytes(re.sub(f'\r\n{header}: .*\r\n', '\r\n', str(raw_request), flags = re.MULTILINE | re.DOTALL))

            request = remove_header(request, patch_header)

            # XXX: i want to puke
            #   this is MVP btw
            first_line, all_headers = request.split('\r\n', 1)
            modified_request = '\r\n'.join([
                first_line,
                filter['output'],
                all_headers
            ])

            print(f'ok request for patched header ({patched_header}):\n\n{modified_request}\n\n----------------------')

            request = self._new_request(modified_request)
            worker.queue(request)
            test_requests.append({
                **filter,
                'request' : request
            })

        # store results

        log.debug(f'Sending a total of {len(worker._queue)} requests to {self.host}:{self.port}...')
        worker.start()
        worker.join()

        return {
            'phase' : phase,
            'filters' : filters_outputs,
            'baseline' : {
                'requests' : baseline_requests
            }
        }

'''
Generate a request and use that for testing smuggling. This is useful for if the
user wants to just pass in a giant list of hosts.
'''
class HostScan(RequestScan):
    def __init__(self, host, **kwargs):
        if 'host' in kwargs:
            del kwargs['host']

        super(RequestScan, self).__init__((
            r'GET / HTTP/1.1\n'
            f'Content-Length: 2'
            f'Host: {host}\n'
            f'Referer: https://{host}/\n'
            r'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36\n\n'
        ), host = host, **kwargs)
