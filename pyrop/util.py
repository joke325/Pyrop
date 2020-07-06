'''Handy functions
'''
__version__ = "0.3.0"

# Copyright (c) 2020 Janky <box@janky.tech>
# All right reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.

from datetime import datetime
from time import mktime
from .rop.lib import pyrop_ref2str, PyRopUtils
from .rop.err import ROPE
from .error import RopError


def _get_rop_string(rop, ret, rop_strs, free_buf=True, clear_buf=False):
    '''F(rop: RopLib, ret: int, rop_strs: string/[string], free_buf: bool) -> string/[string]
    Transforms FFI strings onto strings
    Raises RopError
    '''
    svals = []
    for str_ in (rop_strs if isinstance(rop_strs, list) else (rop_strs,)):
        sval = (pyrop_ref2str(str_) if str_.value is not None else None)
        svals.append(sval)
        if clear_buf and (sval is not None):
            rop.rnp_buffer_clear(str_, len(sval))
        if free_buf:
            rop.rnp_buffer_destroy(str_)
    if ret != ROPE.RNP_SUCCESS:
        raise RopError(ret)
    return svals if len(svals) > 1 else svals[0]

def _get_rop_data(rop, ret, rop_buf, rop_buf_len, free_buf=True):
    '''F(rop: RopLib, ret: int, rop_buf: ctype, rop_buf_len: int, free_buf: bool) -> bytes
    Reads FFI data
    Raises RopError
    '''
    data = None
    if rop_buf.value is not None and rop_buf_len > 0:
        data = PyRopUtils.read_memory(rop_buf, rop_buf_len)
    if free_buf:
        rop.rnp_buffer_destroy(rop_buf)
    if ret != ROPE.RNP_SUCCESS:
        raise RopError(ret)
    return data

def _call_rop_func(fx_, out_count=1, *args):
    '''F(fx_: function, out_count: int, *args: *) -> bytes
    FFI functions call helper
    '''
    outs = [None]
    ret = fx_(*(args + (outs,)*out_count))
    if ret != ROPE.RNP_SUCCESS:
        raise RopError(ret)
    return outs[-1] if out_count < 2 else outs[-out_count:]

def _new_rop_obj(wref, ret, rop_obj, obj_fact, tag):
    '''F(wref: RopBind, ret: int, rop_obj: ctype, obj_fact: function, tag: int) -> object
    Proxies allocator helper
    '''
    obj = None
    if ret == ROPE.RNP_SUCCESS and rop_obj.value is not None:
        obj = obj_fact(wref, rop_obj)
        wref._put_obj(obj, tag)
    if ret != ROPE.RNP_SUCCESS:
        raise RopError(ret)
    return obj

def _get_str_prop(lib, fx_, *ars): return _get_rop_string(lib, ROPE.RNP_SUCCESS, \
    _call_rop_func(fx_, 1, *ars))
def _ts2datetime(tstamp): return datetime.fromtimestamp(tstamp) if tstamp != 0 else None
def _datetime2ts(dtime): return int(mktime(dtime.timetuple())+0.5) if dtime is not None else 0
def _timedelta2sec(tdtime): return int(tdtime.total_seconds()+0.5) if tdtime is not None else 0
