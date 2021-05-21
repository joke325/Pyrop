'''FFI proxy
'''
__version__ = "0.14.0"

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
from .error import RopError
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
        self.__lib = own.lib
        if iiid is None or iiid.value is None:
            raise RopError(self.__own().ROP_ERROR_NULL_HANDLE)
        self.__iiid = iiid

    def _close(self):
        ret = self.__lib.rnp_identifier_iterator_destroy(self.__iiid)
        self.__iiid = None
        return ret

    @property
    def handle(self): return self.__iiid

    def next(self):
        inext = _call_rop_func(self.__lib.rnp_identifier_iterator_next, 1, self.__iiid)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, inext, False)


class RopSession(object):
    '''FFI proxy
    '''

    def __init__(self, own, sid):
        self.__own = weakref(own)
        self.__lib = own.lib
        if sid is None or sid.value is None:
            raise RopError(self.__own().ROP_ERROR_NULL_HANDLE)
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
    def handle(self): return self.__sid
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
        inp = (input_.handle if input_ is not None else None)
        outp = (output.handle if output is not None else None)
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
            ret = self.__lib.rnp_op_generate_subkey_create(outs, self.__sid, primary.handle, key_alg)
        return _new_rop_obj(self.__own(), ret, outs[-1], RopOpGenerate, tag)

    def op_generate_create_subkey(self, key_alg, primary):
        return self.op_generate_create(key_alg, primary)

    def op_encrypt_create(self, input_, output, tag=0):
        outs = []
        inp = (input_.handle if input_ is not None else None)
        outp = (output.handle if output is not None else None)
        ret = self.__lib.rnp_op_encrypt_create(outs, self.__sid, inp, outp)
        return _new_rop_obj(self.__own(), ret, outs[-1], RopOpEncrypt, tag)

    def op_verify_create(self, input_, output=None, signature=None, tag=0):
        outs = []
        inp = (input_.handle if input_ is not None else None)
        if signature is None:
            outp = (output.handle if output is not None else None)
            ret = self.__lib.rnp_op_verify_create(outs, self.__sid, inp, outp)
        else:
            sig = (signature.handle if signature is not None else None)
            ret = self.__lib.rnp_op_verify_detached_create(outs, self.__sid, inp, sig)
        return _new_rop_obj(self.__own(), ret, outs[-1], RopOpVerify, tag)

    def request_password(self, key, context):
        hkey = (key.handle if key is not None else None)
        pswd = _call_rop_func(self.__lib.rnp_request_password, 1, self.__sid, hkey, context)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, pswd, clear_buf=True)

    def load_keys(self, format_, input_, public=True, secret=True):
        inp = (input_.handle if input_ is not None else None)
        flags = (ROPD.RNP_LOAD_SAVE_PUBLIC_KEYS if public else 0)
        flags |= (ROPD.RNP_LOAD_SAVE_SECRET_KEYS if secret else 0)
        _call_rop_func(self.__lib.rnp_load_keys, 0, self.__sid, format_, inp, flags)

    def load_keys_public(self, format_, input_):
        self.load_keys(format_, input_, public=True, secret=False)

    def load_keys_secret(self, format_, input_):
        self.load_keys(format_, input_, public=False, secret=True)

    def unload_keys(self, public=True, secret=True):
        flags = (ROPD.RNP_KEY_UNLOAD_PUBLIC if public else 0)
        flags |= (ROPD.RNP_KEY_UNLOAD_SECRET if secret else 0)
        _call_rop_func(self.__lib.rnp_unload_keys, 0, self.__sid, flags)

    def unload_keys_public(self):
        self.unload_keys(public=True, secret=False)

    def unload_keys_secret(self):
        self.unload_keys(public=False, secret=True)

    def __put_key(self, rop_key, tag):
        return _new_rop_obj(self.__own(), ROPE.RNP_SUCCESS, rop_key, RopKey, tag)

    def locate_key(self, identifier_type, identifier, tag=0):
        key = _call_rop_func(self.__lib.rnp_locate_key, 1, self.__sid, identifier_type, identifier)
        return self.__put_key(key, tag)

    def generate_key_rsa(self, bits, subbits, userid, password, tag=0):
        key = _call_rop_func(self.__lib.rnp_generate_key_rsa, 1, self.__sid, bits, subbits, \
            userid, password)
        return self.__put_key(key, tag)

    def generate_key_dsa_eg(self, bits, subbits, userid, password, tag=0):
        key = _call_rop_func(self.__lib.rnp_generate_key_dsa_eg, 1, self.__sid, bits, subbits, \
            userid, password)
        return self.__put_key(key, tag)

    def generate_key_ec(self, curve, userid, password, tag=0):
        key = _call_rop_func(self.__lib.rnp_generate_key_ec, 1, self.__sid, curve, userid, password)
        return self.__put_key(key, tag)

    def generate_key_25519(self, userid, password, tag=0):
        key = _call_rop_func(self.__lib.rnp_generate_key_25519, 1, self.__sid, userid, password)
        return self.__put_key(key, tag)

    def generate_key_sm2(self, userid, password, tag=0):
        key = _call_rop_func(self.__lib.rnp_generate_key_sm2, 1, self.__sid, userid, password)
        return self.__put_key(key, tag)

    def generate_key_ex(self, key_alg, sub_alg, key_bits, sub_bits, key_curve, sub_curve, \
        userid, password, tag=0):
        key = _call_rop_func(self.__lib.rnp_generate_key_ex, 1, self.__sid, key_alg, sub_alg, \
            key_bits, sub_bits, key_curve, sub_curve, userid, password)
        return self.__put_key(key, tag)

    def import_keys(self, input_, public=True, secret=True, perm=False, sngl=False):
        inp = (input_.handle if input_ is not None else None)
        flags = (ROPD.RNP_LOAD_SAVE_PUBLIC_KEYS if public else 0)
        flags |= (ROPD.RNP_LOAD_SAVE_SECRET_KEYS if secret else 0)
        flags |= (ROPD.RNP_LOAD_SAVE_PERMISSIVE if perm else 0)
        flags |= (ROPD.RNP_LOAD_SAVE_SINGLE if sngl else 0)
        try:
            keys = _call_rop_func(self.__lib.rnp_import_keys, 1, self.__sid, inp, flags)
            return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, keys)
        except RopError as er_:
            if er_.err_code == ROPE.RNP_ERROR_EOF:
                return None
            raise

    def import_keys_public(self, input_, **kwargs):
        return self.import_keys(input_, public=True, secret=False, **kwargs)

    def import_keys_secret(self, input_, **kwargs):
        return self.import_keys(input_, public=False, secret=True, **kwargs)

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

    def import_signatures(self, input_):
        inp = (input_.handle if input_ is not None else None)
        sigs = _call_rop_func(self.__lib.rnp_import_signatures, 1, self.__sid, inp, 0)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, sigs)

    def save_keys(self, format_, output, public=True, secret=True):
        outp = (output.handle if output is not None else None)
        flags = (ROPD.RNP_LOAD_SAVE_PUBLIC_KEYS if public else 0)
        flags |= (ROPD.RNP_LOAD_SAVE_SECRET_KEYS if secret else 0)
        _call_rop_func(self.__lib.rnp_save_keys, 0, self.__sid, format_, outp, flags)

    def save_keys_public(self, format_, output):
        self.save_keys(format_, output, public=True, secret=False)

    def save_keys_secret(self, format_, output):
        self.save_keys(format_, output, public=False, secret=True)

    def generate_key_json(self, json):
        return _get_str_prop(self.__lib, self.__lib.rnp_generate_key_json, self.__sid, json)

    def decrypt(self, input_, output):
        inp = (input_.handle if input_ is not None else None)
        outp = (output.handle if output is not None else None)
        _call_rop_func(self.__lib.rnp_decrypt, 0, self.__sid, inp, outp)

    # Callback proxies

    def __reshape_password_cb(self, function):
        '''F(RopSession, string, RopKey, string) -> bool
        '''
        def cb_wrap(ffi, app_ctx, key, pgp_context, buf_len):
            atag = self.__own().tagging()
            # create new Session and Key handlers
            rop_ses = None
            rop_key = None
            try:
                rop_ses = _new_rop_obj(self.__own(), ROPE.RNP_SUCCESS, c_void_p(ffi), RopSession, atag)
                rop_key = _new_rop_obj(self.__own(), ROPE.RNP_SUCCESS, c_void_p(key), RopKey, atag) if key is not None else None
                return function(rop_ses, app_ctx, rop_key, pgp_context, buf_len)
            except RopError: pass
            finally:
                if rop_ses is not None:
                    rop_ses._detach()
                if rop_key is not None:
                    rop_key._detach()
                self.__own().drop(atag)
            return False, None
        return cb_wrap

    def __reshape_key_cb(self, function):
        '''F(RopSession, string, string, string, bool) -> None
        '''
        def cb_wrap(ffi, app_ctx, identifier_type, identifier, secret):
            atag = self.__own().tagging()
            # create a new Session handler
            rop_ses = None
            try:
                rop_ses = _new_rop_obj(self.__own(), ROPE.RNP_SUCCESS, c_void_p(ffi), RopSession, atag)
                function(rop_ses, app_ctx, identifier_type, \
                        identifier, secret)
            except RopError: pass
            finally:
                if rop_ses is not None:
                    rop_ses._detach()
                self.__own().drop(atag)
            return 0
        return cb_wrap
