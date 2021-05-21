'''Ops proxies
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
from .rop.err import ROPE
from .error import RopError
from .util import _call_rop_func, _new_rop_obj, _get_rop_string, _timedelta2sec, \
    _ts2datetime, _datetime2ts
from .key import RopKey
from .sign import RopSign


class RopSignSignature(object):
    '''OP Sign Signature proxy
    '''

    def __init__(self, own, sgid):
        self.__own = weakref(own)
        self.__lib = own.lib
        if sgid is None or sgid.value is None:
            raise RopError(self.__own().ROP_ERROR_NULL_HANDLE)
        self.__sgid = sgid

    @property
    def handle(self): return self.__sgid

    # API

    def set_hash(self, hash_):
        _call_rop_func(self.__lib.rnp_op_sign_signature_set_hash, 0, self.__sgid, hash_)

    def set_creation_time(self, create):
        _call_rop_func(self.__lib.rnp_op_sign_signature_set_creation_time, 0, self.__sgid, \
            _datetime2ts(create))

    def set_expiration_time(self, expires):
        _call_rop_func(self.__lib.rnp_op_sign_signature_set_expiration_time, 0, self.__sgid, \
            _datetime2ts(expires))


class RopOpSign(object):
    '''OP Sign proxy
    '''

    def __init__(self, own, opid):
        self.__own = weakref(own)
        self.__lib = own.lib
        if opid is None or opid.value is None:
            raise RopError(self.__own().ROP_ERROR_NULL_HANDLE)
        self.__opid = opid

    def _close(self):
        ret = self.__lib.rnp_op_sign_destroy(self.__opid)
        self.__opid = None
        return ret

    @property
    def handle(self): return self.__opid

    # API

    def set_compression(self, compression, level):
        _call_rop_func(self.__lib.rnp_op_sign_set_compression, 0, self.__opid, compression, level)

    def set_armor(self, armored):
        _call_rop_func(self.__lib.rnp_op_sign_set_armor, 0, self.__opid, armored)

    def set_hash(self, hash_):
        _call_rop_func(self.__lib.rnp_op_sign_set_hash, 0, self.__opid, hash_)

    def set_creation_time(self, create):
        _call_rop_func(self.__lib.rnp_op_sign_set_creation_time, 0, self.__opid, \
            _datetime2ts(create))

    def set_expiration_time(self, expire):
        _call_rop_func(self.__lib.rnp_op_sign_set_expiration_time, 0, self.__opid, \
            _datetime2ts(expire))

    def set_expiration(self, expiration):
        _call_rop_func(self.__lib.rnp_op_sign_set_expiration_time, 0, self.__opid, \
            _timedelta2sec(expiration))

    def set_file_name(self, filename):
        _call_rop_func(self.__lib.rnp_op_sign_set_file_name, 0, self.__opid, filename)

    def set_file_mtime(self, mtime):
        _call_rop_func(self.__lib.rnp_op_sign_set_file_mtime, 0, self.__opid, \
            _datetime2ts(mtime))

    def execute(self):
        _call_rop_func(self.__lib.rnp_op_sign_execute, 0, self.__opid)

    def add_signature(self, key):
        hkey = (key.handle if key is not None else None)
        sig = _call_rop_func(self.__lib.rnp_op_sign_add_signature, 1, self.__opid, hkey)
        return RopSignSignature(self.__own(), sig)


class RopOpGenerate(object):
    '''OP Generate proxy
    '''

    def __init__(self, own, opid):
        self.__own = weakref(own)
        self.__lib = own.lib
        if opid is None or opid.value is None:
            raise RopError(self.__own().ROP_ERROR_NULL_HANDLE)
        self.__opid = opid

    def _close(self):
        ret = self.__lib.rnp_op_generate_destroy(self.__opid)
        self.__opid = None
        return ret

    @property
    def handle(self): return self.__opid

    # API

    def set_bits(self, bits):
        _call_rop_func(self.__lib.rnp_op_generate_set_bits, 0, self.__opid, bits)

    def set_hash(self, hash_):
        _call_rop_func(self.__lib.rnp_op_generate_set_hash, 0, self.__opid, hash_)

    def set_dsa_qbits(self, qbits):
        _call_rop_func(self.__lib.rnp_op_generate_set_dsa_qbits, 0, self.__opid, qbits)

    def set_curve(self, curve):
        _call_rop_func(self.__lib.rnp_op_generate_set_curve, 0, self.__opid, curve)

    def set_protection_password(self, password):
        _call_rop_func(self.__lib.rnp_op_generate_set_protection_password, 0, self.__opid, password)

    def set_request_password(self, request):
        _call_rop_func(self.__lib.rnp_op_generate_set_request_password, 0, self.__opid, request)

    def set_protection_cipher(self, cipher):
        _call_rop_func(self.__lib.rnp_op_generate_set_protection_cipher, 0, self.__opid, cipher)

    def set_protection_hash(self, hash_):
        _call_rop_func(self.__lib.rnp_op_generate_set_protection_hash, 0, self.__opid, hash_)

    def set_protection_mode(self, mode):
        _call_rop_func(self.__lib.rnp_op_generate_set_protection_mode, 0, self.__opid, mode)

    def set_protection_iterations(self, iterations):
        _call_rop_func(self.__lib.rnp_op_generate_set_protection_iterations, 0, self.__opid, \
            iterations)

    def add_usage(self, usage):
        _call_rop_func(self.__lib.rnp_op_generate_add_usage, 0, self.__opid, usage)

    def clear_usage(self):
        _call_rop_func(self.__lib.rnp_op_generate_clear_usage, 0, self.__opid)

    def set_usages(self, usages):
        self.clear_usage()
        for usage in usages:
            self.add_usage(usage)

    def set_userid(self, userid):
        _call_rop_func(self.__lib.rnp_op_generate_set_userid, 0, self.__opid, userid)

    def set_expiration(self, expiration):
        _call_rop_func(self.__lib.rnp_op_generate_set_expiration, 0, self.__opid, \
            _timedelta2sec(expiration))

    def add_pref_hash(self, hash_):
        _call_rop_func(self.__lib.rnp_op_generate_add_pref_hash, 0, self.__opid, hash_)

    def clear_pref_hashes(self):
        _call_rop_func(self.__lib.rnp_op_generate_clear_pref_hashes, 0, self.__opid)

    def set_pref_hashes(self, hashes):
        self.clear_pref_hashes()
        for hash_ in hashes:
            self.add_pref_hash(hash_)

    def add_pref_compression(self, compression):
        _call_rop_func(self.__lib.rnp_op_generate_add_pref_compression, 0, self.__opid, compression)

    def clear_pref_compression(self):
        _call_rop_func(self.__lib.rnp_op_generate_clear_pref_compression, 0, self.__opid)

    def set_pref_compressions(self, compressions):
        self.clear_pref_compression()
        for compression in compressions:
            self.add_pref_compression(compression)

    def add_pref_cipher(self, cipher):
        _call_rop_func(self.__lib.rnp_op_generate_add_pref_cipher, 0, self.__opid, cipher)

    def clear_pref_ciphers(self):
        _call_rop_func(self.__lib.rnp_op_generate_clear_pref_ciphers, 0, self.__opid)

    def set_pref_ciphers(self, ciphers):
        self.clear_pref_ciphers()
        for cipher in ciphers:
            self.add_pref_cipher(cipher)

    def set_pref_keyserver(self, keyserver):
        _call_rop_func(self.__lib.rnp_op_generate_set_pref_keyserver, 0, self.__opid, keyserver)

    def execute(self):
        _call_rop_func(self.__lib.rnp_op_generate_execute, 0, self.__opid)

    def get_key(self, tag=0):
        handle = _call_rop_func(self.__lib.rnp_op_generate_get_key, 1, self.__opid)
        return _new_rop_obj(self.__own(), ROPE.RNP_SUCCESS, handle, RopKey, tag)


class RopOpEncrypt(object):
    '''OP Encrypt proxy
    '''

    def __init__(self, own, opid):
        self.__own = weakref(own)
        self.__lib = own.lib
        if opid is None or opid.value is None:
            raise RopError(self.__own().ROP_ERROR_NULL_HANDLE)
        self.__opid = opid

    def _close(self):
        ret = self.__lib.rnp_op_encrypt_destroy(self.__opid)
        self.__opid = None
        return ret

    @property
    def handle(self): return self.__opid

    # API

    def add_recipient(self, key):
        hkey = (key.handle if key is not None else None)
        _call_rop_func(self.__lib.rnp_op_encrypt_add_recipient, 0, self.__opid, hkey)

    def add_signature(self, key):
        hkey = (key.handle if key is not None else None)
        hop = _call_rop_func(self.__lib.rnp_op_encrypt_add_signature, 1, self.__opid, hkey)
        return RopSignSignature(self.__own(), hop)

    def set_hash(self, hash_):
        _call_rop_func(self.__lib.rnp_op_encrypt_set_hash, 0, self.__opid, hash_)

    def set_creation_time(self, create):
        _call_rop_func(self.__lib.rnp_op_encrypt_set_creation_time, 0, self.__opid, \
            _datetime2ts(create))

    def set_expiration_time(self, expire):
        _call_rop_func(self.__lib.rnp_op_encrypt_set_expiration_time, 0, self.__opid, \
            _datetime2ts(expire))

    def add_password(self, password, s2k_hash, iterations, s2k_cipher):
        _call_rop_func(self.__lib.rnp_op_encrypt_add_password, 0, self.__opid, password, \
            s2k_hash, iterations, s2k_cipher)

    def set_armor(self, armored):
        _call_rop_func(self.__lib.rnp_op_encrypt_set_armor, 0, self.__opid, armored)

    def set_cipher(self, cipher):
        _call_rop_func(self.__lib.rnp_op_encrypt_set_cipher, 0, self.__opid, cipher)

    def set_aead(self, alg):
        _call_rop_func(self.__lib.rnp_op_encrypt_set_aead, 0, self.__opid, alg)

    def set_aead_bits(self, bits):
        _call_rop_func(self.__lib.rnp_op_encrypt_set_aead_bits, 0, self.__opid, bits)

    def set_compression(self, compression, level):
        _call_rop_func(self.__lib.rnp_op_encrypt_set_compression, 0, self.__opid, \
            compression, level)

    def set_file_name(self, filename):
        _call_rop_func(self.__lib.rnp_op_encrypt_set_file_name, 0, self.__opid, filename)

    def set_file_mtime(self, mtime):
        _call_rop_func(self.__lib.rnp_op_encrypt_set_file_mtime, 0, self.__opid, \
            _datetime2ts(mtime))

    def execute(self):
        _call_rop_func(self.__lib.rnp_op_encrypt_execute, 0, self.__opid)


class RopVeriSignature(object):
    '''OP Verify Signature proxy
    '''

    def __init__(self, own, sgid):
        self.__own = weakref(own)
        self.__lib = own.lib
        if sgid is None or sgid.value is None:
            raise RopError(self.__own().ROP_ERROR_NULL_HANDLE)
        self.__sgid = sgid

    @property
    def handle(self): return self.__sgid

    # API

    @property
    def hash(self):
        hash_ = _call_rop_func(self.__lib.rnp_op_verify_signature_get_hash, 1, self.__sgid)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, hash_)
    @property
    def status(self):
        return self.__lib.rnp_op_verify_signature_get_status(self.__sgid)

    def get_handle(self, tag=0):
        handle = _call_rop_func(self.__lib.rnp_op_verify_signature_get_handle, 1, self.__sgid)
        return _new_rop_obj(self.__own(), ROPE.RNP_SUCCESS, handle, RopSign, tag)

    def get_key(self, tag=0):
        hkey = _call_rop_func(self.__lib.rnp_op_verify_signature_get_key, 1, self.__sgid)
        return _new_rop_obj(self.__own(), ROPE.RNP_SUCCESS, hkey, RopKey, tag)

    def get_times(self):
        tm1, tm2 = _call_rop_func(self.__lib.rnp_op_verify_signature_get_times, 2, self.__sgid)
        return _ts2datetime(tm1), _ts2datetime(tm2)


class RopRecipient(object):
    '''OP Recipient
    '''

    def __init__(self, own, rid):
        self.__own = weakref(own)
        self.__lib = own.lib
        if rid is None or rid.value is None:
            raise RopError(self.__own().ROP_ERROR_NULL_HANDLE)
        self.__rid = rid

    @property
    def handle(self): return self.__rid

    # API

    @property
    def keyid(self):
        kid = _call_rop_func(self.__lib.rnp_recipient_get_keyid, 1, self.__rid)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, kid)
    @property
    def alg(self):
        alg = _call_rop_func(self.__lib.rnp_recipient_get_alg, 1, self.__rid)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, alg)


class RopSymEnc(object):
    '''OP Symenc
    '''

    def __init__(self, own, seid):
        self.__own = weakref(own)
        self.__lib = own.lib
        if seid is None or seid.value is None:
            raise RopError(self.__own().ROP_ERROR_NULL_HANDLE)
        self.__seid = seid

    @property
    def handle(self): return self.__seid

    # API

    @property
    def cipher(self):
        cip = _call_rop_func(self.__lib.rnp_symenc_get_cipher, 1, self.__seid)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, cip)
    @property
    def aead_alg(self):
        alg = _call_rop_func(self.__lib.rnp_symenc_get_aead_alg, 1, self.__seid)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, alg)
    @property
    def hash_alg(self):
        alg = _call_rop_func(self.__lib.rnp_symenc_get_hash_alg, 1, self.__seid)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, alg)
    @property
    def s2k_type(self):
        s2k = _call_rop_func(self.__lib.rnp_symenc_get_s2k_type, 1, self.__seid)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, s2k)
    @property
    def s2k_iterations(self):
        return _call_rop_func(self.__lib.rnp_symenc_get_s2k_iterations, 1, self.__seid)


class RopOpVerify(object):
    '''OP Verify proxy
    '''

    def __init__(self, own, opid):
        self.__own = weakref(own)
        self.__lib = own.lib
        if opid is None or opid.value is None:
            raise RopError(self.__own().ROP_ERROR_NULL_HANDLE)
        self.__opid = opid

    def _close(self):
        ret = self.__lib.rnp_op_verify_destroy(self.__opid)
        self.__opid = None
        return ret

    @property
    def handle(self): return self.__opid

    # API

    @property
    def signature_count(self):
        return _call_rop_func(self.__lib.rnp_op_verify_get_signature_count, 1, self.__opid)

    def execute(self):
        _call_rop_func(self.__lib.rnp_op_verify_execute, 0, self.__opid)

    def get_signature_at(self, idx):
        sig = _call_rop_func(self.__lib.rnp_op_verify_get_signature_at, 1, self.__opid, idx)
        return RopVeriSignature(self.__own(), sig)

    def get_file_info(self):
        filename, mtime = _call_rop_func(self.__lib.rnp_op_verify_get_file_info, 2, self.__opid)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, filename), _ts2datetime(mtime)

    def get_protection_info(self):
        # F() -> (mode: str, cipher: str, valid: bool)
        mode, cipher, valid = _call_rop_func(self.__lib.rnp_op_verify_get_protection_info, 3, self.__opid)
        cipher = _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, cipher)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, mode), cipher, valid

    @property
    def recipient_count(self):
        return _call_rop_func(self.__lib.rnp_op_verify_get_recipient_count, 1, self.__opid)
    @property
    def used_recipient(self):
        rcp = _call_rop_func(self.__lib.rnp_op_verify_get_used_recipient, 1, self.__opid)
        return RopRecipient(self.__own(), rcp) if rcp.value is not None else None

    def get_recipient_at(self, idx):
        rcp = _call_rop_func(self.__lib.rnp_op_verify_get_recipient_at, 1, self.__opid, idx)
        return RopRecipient(self.__own(), rcp) if rcp.value is not None else None

    @property
    def symenc_count(self):
        return _call_rop_func(self.__lib.rnp_op_verify_get_symenc_count, 1, self.__opid)
    @property
    def used_symenc(self):
        senc = _call_rop_func(self.__lib.rnp_op_verify_get_used_symenc, 1, self.__opid)
        return RopSymEnc(self.__own(), senc) if senc.value is not None else None

    def get_symenc_at(self, idx):
        senc = _call_rop_func(self.__lib.rnp_op_verify_get_symenc_at, 1, self.__opid, idx)
        return RopSymEnc(self.__own(), senc) if senc.value is not None else None
