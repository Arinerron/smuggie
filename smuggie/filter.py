#/usr/bin/env python3
# Author: Aaron Esau <python@aaronesau.com>
#
# This module contains a bunch of functions to manipulate a single header to
# bypass filters with.

from smartbytes import *

import functools

RISK_LEVEL_HIGH, RISK_LEVEL_MEDIUM, RISK_LEVEL_LOW = 3, 2, 1
DEFAULT_HEADER = '{key}: {val}'


def formatter(format = DEFAULT_HEADER):
    return format.format


# https://github.com/PortSwigger/http-request-smuggler/blob/master/src/burp/DesyncBox.java
# TODO: auto-generate higher-risk values for all ASCII etc
FILTERS = {
    'space_before' : {
        'method' : formatter(' {key}: {val}'),
        'level' : RISK_LEVEL_LOW
    },

    'tab_before' : {
        'method' : formatter('\t{key}: {val}'),
        'level' : RISK_LEVEL_LOW
    },

    'nospace_between' : {
        'method' : formatter('{key}:{val}'),
        'level' : RISK_LEVEL_LOW
    },

    'tab_between' : {
        'method' : formatter('{key}:\t{val}'),
        'level' : RISK_LEVEL_LOW
    },

    'space_between_before' : {
        'method' : formatter('{key} : {val}'),
        'level' : RISK_LEVEL_LOW
    }
}


def format_header(header, max_level = RISK_LEVEL_MEDIUM):
    # XXX: this code is hacky and buggy and should be rewritten! :(
    key, val = smartbytes(header).strip().remove(' ').split(':')

    # find all filters within our risk level
    filters = {
        (name : filter if filter['level'] <= max_level)
        for name, filter in FILTERS.items()
    }

    filter_outputs = set()
    ret_val = set()

    # get all unique filters (by output)
    for name, filter in filters.items():
        filter_output = filter['method'](key = key, val = val)

        if filter_output in filter_outputs:
            continue

        filter_outputs.add(filter_output)
        ret_val.add({
            'name' : name,
            'output' : filter_output,
            **filter
        })

    return ret_val
