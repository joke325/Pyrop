'''I/O proxies
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

from weakref import ref as weakref
from .rop.lib import ROPD
from .rop.err import ROPE
from .error import RopError
from .util import _call_rop_func, _new_rop_obj, _get_str_prop, _get_rop_data


class RopInput(object):
    '''Input ops proxy
    '''

    def __init__(self, own, iid):
        self.__own = weakref(own)
        self.__lib = own.lib
        if iid is None or iid.value is None:
            raise RopError(ROP_ERROR_NULL_HANDLE)
        self.__iid = iid
        self._reader = None
        self._rcloser = None

    def _close(self):
        ret = self.__lib.rnp_input_destroy(self.__iid)
        self.__iid = None
        return ret

    @property
    def handle(self): return self.__iid

    # API

    def dump_packets_to_json(self, mpi=False, raw=False, grip=False):
        flags = (ROPD.RNP_JSON_DUMP_MPI if mpi else 0)
        flags |= (ROPD.RNP_JSON_DUMP_RAW if raw else 0)
        flags |= (ROPD.RNP_JSON_DUMP_GRIP if grip else 0)
        return _get_str_prop(self.__lib, self.__lib.rnp_dump_packets_to_json, self.__iid, flags)

    def dump_packets_to_output(self, output, mpi=False, raw=False, grip=False):
        flags = (ROPD.RNP_DUMP_MPI if mpi else 0)
        flags |= (ROPD.RNP_DUMP_RAW if raw else 0)
        flags |= (ROPD.RNP_DUMP_GRIP if grip else 0)
        _call_rop_func(self.__lib.rnp_dump_packets_to_output, 0, self.__iid, output.handle, flags)

    def enarmor(self, output, type_):
        _call_rop_func(self.__lib.rnp_enarmor, 0, self.__iid, output.handle, type_)

    def dearmor(self, output):
        _call_rop_func(self.__lib.rnp_dearmor, 0, self.__iid, output.handle)

    def guess_contents(self):
        return _get_str_prop(self.__lib, self.__lib.rnp_guess_contents, self.__iid)


class RopOutput(object):
    '''Output ops proxy
    '''

    def __init__(self, own, oid):
        self.__own = weakref(own)
        self.__lib = own.lib
        if oid is None or oid.value is None:
            raise RopError(ROP_ERROR_NULL_HANDLE)
        self.__oid = oid
        self._writer = None
        self._wcloser = None

    def _close(self):
        ret = self.__lib.rnp_output_finish(self.__oid)
        ret2 = self.__lib.rnp_output_destroy(self.__oid)
        ret = ret2 if ret == ROPE.RNP_SUCCESS and ret2 != ROPE.RNP_SUCCESS else ret
        self.__oid = None
        return ret

    @property
    def handle(self): return self.__oid

    # API

    def output_to_armor(self, type_, tag=0):
        outs = []
        ret = self.__lib.rnp_output_to_armor(self.__oid, outs, type_)
        return _new_rop_obj(self.__own(), ret, outs[-1], RopOutput, tag)

    def memory_get_buf(self, do_copy):
        outs = []
        ret = self.__lib.rnp_output_memory_get_buf(self.__oid, outs, outs, do_copy)
        if ret != ROPE.RNP_SUCCESS:
            raise RopError(ret)
        return _get_rop_data(self.__lib, ret, outs[-2], outs[-1], free_buf=do_copy)

    def memory_get_str(self, do_copy):
        return self.memory_get_buf(do_copy)

    def write(self, data, size):
        return _call_rop_func(self.__lib.rnp_output_write, 1, self.__oid, data, size)
