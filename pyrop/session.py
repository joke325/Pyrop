'''FFI proxy
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
from ctypes import c_void_p
from .rop.lib import RopLib, PyRopUtils, ROPD
from .rop.err import ROPE
from .util import _call_rop_func, _new_rop_obj, _get_rop_string, _get_str_prop
from .key import RopKey
from .op import RopOpGenerate, RopOpEncrypt, RopOpVerify, RopOpSign


class RopIdIterator(object):
    '''Identifier Iterator proxy
    '''

    def __init__(self, own, iiid):
        self.__own = weakref(own)
        self.__lib = own._lib
        self.__iiid = iiid

    def _close(self):
        ret = self.__lib.rnp_identifier_iterator_destroy(self.__iiid)
        self.__iiid = None
        return ret

    def next(self):
        inext = _call_rop_func(self.__lib.rnp_identifier_iterator_next, 1, self.__iiid)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, inext, False)


class RopSession(object):
    '''FFI proxy
    '''

    def __init__(self, own, sid):
        self.__own = weakref(own)
        self.__lib = own._lib
        self.__sid = sid
        self.__pass_provider = None
        self.__key_provider = None

    def _close(self):
        ret = ROPE.RNP_SUCCESS
        if self.__sid is not None:
            ret = self.__lib.rnp_ffi_destroy(self.__sid)
            self.__sid = None
        return ret

    def _detach(self):
        self.__sid = None

    @property
    def bind(self): return self.__own()

    #API

    @property
    def public_key_count(self):
        return _call_rop_func(self.__lib.rnp_get_public_key_count, 1, self.__sid)
    @property
    def secret_key_count(self):
        return _call_rop_func(self.__lib.rnp_get_secret_key_count, 1, self.__sid)

    def op_sign_create(self, input_, output, cleartext=False, detached=False, tag=0):
        ret = self.__own().ROP_ERROR_BAD_PARAMETERS
        outs = []
        inp = (input_.in_put if input_ is not None else None)
        outp = (output.out_put if output is not None else None)
        if cleartext:
            ret = self.__lib.rnp_op_sign_cleartext_create(outs, self.__sid, inp, outp)
        elif detached:
            ret = self.__lib.rnp_op_sign_detached_create(outs, self.__sid, inp, outp)
        else:
            ret = self.__lib.rnp_op_sign_create(outs, self.__sid, inp, outp)
        return _new_rop_obj(self.__own(), ret, outs[-1], RopOpSign, tag)

    def op_generate_create(self, key_alg, primary=None, tag=0):
        outs = []
        if primary is None:
            ret = self.__lib.rnp_op_generate_create(outs, self.__sid, key_alg)
        else:
            ret = self.__lib.rnp_op_generate_subkey_create(outs, self.__sid, primary.key, key_alg)
        return _new_rop_obj(self.__own(), ret, outs[-1], RopOpGenerate, tag)

    def op_encrypt_create(self, input_, output, tag=0):
        outs = []
        inp = (input_.in_put if input_ is not None else None)
        outp = (output.out_put if output is not None else None)
        ret = self.__lib.rnp_op_encrypt_create(outs, self.__sid, inp, outp)
        return _new_rop_obj(self.__own(), ret, outs[-1], RopOpEncrypt, tag)

    def op_verify_create(self, input_, output=None, signature=None, tag=0):
        outs = []
        inp = (input_.in_put if input_ is not None else None)
        if signature is None:
            outp = (output.out_put if output is not None else None)
            ret = self.__lib.rnp_op_verify_create(outs, self.__sid, inp, outp)
        else:
            sig = (signature.in_put if signature is not None else None)
            ret = self.__lib.rnp_op_verify_detached_create(outs, self.__sid, inp, sig)
        return _new_rop_obj(self.__own(), ret, outs[-1], RopOpVerify, tag)

    def load_keys(self, format_, input_, public=False, secret=False):
        inp = (input_.in_put if input_ is not None else None)
        flags = (ROPD.RNP_LOAD_SAVE_PUBLIC_KEYS if public else 0)
        flags |= (ROPD.RNP_LOAD_SAVE_SECRET_KEYS if secret else 0)
        _call_rop_func(self.__lib.rnp_load_keys, 0, self.__sid, format_, inp, flags)

    def unload_keys(self, public=False, secret=False):
        flags = (ROPD.RNP_KEY_UNLOAD_PUBLIC if public else 0)
        flags |= (ROPD.RNP_KEY_UNLOAD_SECRET if secret else 0)
        _call_rop_func(self.__lib.rnp_unload_keys, 0, self.__sid, flags)

    def _put_key(self, rop_key, tag):
        return _new_rop_obj(self.__own(), ROPE.RNP_SUCCESS, rop_key, RopKey, tag)

    def locate_key(self, identifier_type, identifier, tag=0):
        key = _call_rop_func(self.__lib.rnp_locate_key, 1, self.__sid, identifier_type, identifier)
        return self._put_key(key, tag)

    def generate_key_rsa(self, bits, subbits, userid, password, tag=0):
        key = _call_rop_func(self.__lib.rnp_generate_key_rsa, 1, self.__sid, bits, subbits, \
            userid, password)
        return self._put_key(key, tag)

    def generate_key_dsa_eg(self, bits, subbits, userid, password, tag=0):
        key = _call_rop_func(self.__lib.rnp_generate_key_dsa_eg, 1, self.__sid, bits, subbits, \
            userid, password)
        return self._put_key(key, tag)

    def generate_key_ec(self, curve, userid, password, tag=0):
        key = _call_rop_func(self.__lib.rnp_generate_key_ec, 1, self.__sid, curve, userid, password)
        return self._put_key(key, tag)

    def generate_key_25519(self, userid, password, tag=0):
        key = _call_rop_func(self.__lib.rnp_generate_key_25519, 1, self.__sid, userid, password)
        return self._put_key(key, tag)

    def generate_key_sm2(self, userid, password, tag=0):
        key = _call_rop_func(self.__lib.rnp_generate_key_sm2, 1, self.__sid, userid, password)
        return self._put_key(key, tag)

    def generate_key_ex(self, key_alg, sub_alg, key_bits, sub_bits, key_curve, sub_curve, \
        userid, password, tag=0):
        key = _call_rop_func(self.__lib.rnp_generate_key_ex, 1, self.__sid, key_alg, sub_alg, \
            key_bits, sub_bits, key_curve, sub_curve, userid, password)
        return self._put_key(key, tag)

    def import_keys(self, input_, public=False, secret=False):
        inp = (input_.in_put if input_ is not None else None)
        flags = (ROPD.RNP_LOAD_SAVE_PUBLIC_KEYS if public else 0)
        flags += (ROPD.RNP_LOAD_SAVE_SECRET_KEYS if secret else 0)
        keys = _call_rop_func(self.__lib.rnp_import_keys, 1, self.__sid, inp, flags)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, keys)

    def set_pass_provider(self, getpasscb, getpasscb_ctx):
        self.__pass_provider = RopLib.Rop_password_cb(PyRopUtils.reshape_password_cb( \
            self.__reshape_password_cb(getpasscb))) if getpasscb is not None else \
                RopLib.Rop_password_cb()
        _call_rop_func(self.__lib.rnp_ffi_set_pass_provider, 0, self.__sid, self.__pass_provider, \
            getpasscb_ctx)

    def identifier_iterator_create(self, identifier_type, tag=0):
        outs = []
        ret = self.__lib.rnp_identifier_iterator_create(self.__sid, outs, identifier_type)
        return _new_rop_obj(self.__own(), ret, outs[-1], RopIdIterator, tag)

    def set_log_fd(self, fd_):
        _call_rop_func(self.__lib.rnp_ffi_set_log_fd, 0, self.__sid, fd_)

    def set_key_provider(self, getkeycb, getkeycb_ctx):
        self.__key_provider = RopLib.Rop_get_key_cb(self.__reshape_key_cb(getkeycb)) \
            if getkeycb is not None else RopLib.Rop_get_key_cb()
        _call_rop_func(self.__lib.rnp_ffi_set_key_provider, 0, self.__sid, \
            self.__key_provider, getkeycb_ctx)

    def save_keys(self, format_, output, public=False, secret=False):
        outp = (output.out_put if output is not None else None)
        flags = (ROPD.RNP_LOAD_SAVE_PUBLIC_KEYS if public else 0)
        flags |= (ROPD.RNP_LOAD_SAVE_SECRET_KEYS if secret else 0)
        _call_rop_func(self.__lib.rnp_save_keys, 0, self.__sid, format_, outp, flags)

    def generate_key_json(self, json):
        return _get_str_prop(self.__lib, self.__lib.rnp_generate_key_json, self.__sid, json)

    def decrypt(self, input_, output):
        inp = (input_.in_put if input_ is not None else None)
        outp = (output.out_put if output is not None else None)
        _call_rop_func(self.__lib.rnp_decrypt, 0, self.__sid, inp, outp)

    # Callback proxies

    def __reshape_password_cb(self, function):
        '''F(RopSession, string, RopKey, string) -> bool
        '''
        def cb_wrap(ffi, app_ctx, key, pgp_context, buf_len):
            atag = self.__own().tagging()
            # create new Session and Key handlers
            rop_ses = _new_rop_obj(self.__own(), ROPE.RNP_SUCCESS, c_void_p(ffi), RopSession, atag)
            rop_key = _new_rop_obj(self.__own(), ROPE.RNP_SUCCESS, c_void_p(key), RopKey, atag)
            ret, ret_buf = function(rop_ses, app_ctx, rop_key, pgp_context, buf_len)
            if rop_ses is not None:
                rop_ses._detach()
            if rop_key is not None:
                rop_key._detach()
            self.__own().drop(atag)
            return ret, ret_buf
        return cb_wrap

    def __reshape_key_cb(self, function):
        '''F(RopSession, string, string, string, bool) -> None
        '''
        def cb_wrap(ffi, app_ctx, identifier_type, identifier, secret):
            atag = self.__own().tagging()
            # create a new Session handler
            rop_ses = _new_rop_obj(self.__own(), ROPE.RNP_SUCCESS, c_void_p(ffi), RopSession, atag)
            function(rop_ses, app_ctx, identifier_type, identifier, secret)
            if rop_ses is not None:
                rop_ses._detach()
            self.__own().drop(atag)
            return 0
        return cb_wrap
