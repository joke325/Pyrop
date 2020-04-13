'''Sign proxy
'''
__version__ = "0.1.0"

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
from .util import _call_rop_func, _new_rop_obj, _get_rop_string, _ts2datetime
from .key import RopKey


class RopSign(object):
    '''Signature proxy
    '''

    def __init__(self, own, sgid):
        self.__own = weakref(own)
        self.__lib = own._lib
        self.__sgid = sgid

    def _close(self):
        ret = self.__lib.rnp_signature_handle_destroy(self.__sgid)
        self.__sgid = None
        return ret

    # API

    @property
    def alg(self):
        alg = _call_rop_func(self.__lib.rnp_signature_get_alg, 1, self.__sgid)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, alg)
    @property
    def hash_alg(self):
        alg = _call_rop_func(self.__lib.rnp_signature_get_hash_alg, 1, self.__sgid)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, alg)
    @property
    def creation(self):
        tms = _call_rop_func(self.__lib.rnp_signature_get_creation, 1, self.__sgid)
        return _ts2datetime(tms)
    @property
    def keyid(self):
        kid = _call_rop_func(self.__lib.rnp_signature_get_keyid, 1, self.__sgid)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, kid)

    def get_signer(self, tag=0):
        signer = _call_rop_func(self.__lib.rnp_signature_get_signer, 1, self.__sgid)
        return _new_rop_obj(self.__own(), ROPE.RNP_SUCCESS, signer, RopKey, tag)

    def to_json(self, mpi=False, raw=False, grip=False):
        flags = (ROPD.RNP_JSON_DUMP_MPI if mpi else 0)
        flags |= (ROPD.RNP_JSON_DUMP_RAW if raw else 0)
        flags |= (ROPD.RNP_JSON_DUMP_GRIP if grip else 0)
        json = _call_rop_func(self.__lib.rnp_signature_packet_to_json, 1, self.__sgid, flags)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, json)
