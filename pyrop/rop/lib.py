#!/usr/bin/env python

'''Library wrapper
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

from ctypes import cdll, cast, create_string_buffer, set_conversion_mode
from ctypes import addressof, sizeof, memmove, CFUNCTYPE, POINTER, byref
from ctypes import c_char, c_ubyte, c_int, c_uint, c_size_t, c_ulonglong
from ctypes import c_bool, c_char_p, c_void_p, py_object
from ctypes.util import find_library

class RopLib(object):
    '''Library wrapper
    '''

    __roplib_name = 'rnp-0'     # RNP library name
    string8_format = 'utf-8'    # Input/output strings encoding

    # Callback types
    Rop_get_key_cb = CFUNCTYPE(c_int, c_void_p, py_object, c_char_p, \
        c_char_p, c_bool)
    Rop_password_cb = CFUNCTYPE(c_bool, c_void_p, py_object, c_void_p, \
        c_char_p, POINTER(c_char), c_size_t)
    Rop_input_reader_t = CFUNCTYPE(c_bool, py_object, c_void_p, c_size_t, POINTER(c_size_t))
    Rop_input_closer_t = CFUNCTYPE(c_int, c_void_p)
    Rop_output_writer_t = CFUNCTYPE(c_bool, c_void_p, c_void_p, c_size_t)
    Rop_output_closer_t = CFUNCTYPE(c_int, c_void_p, c_bool)


    def __init__(self, lib_name=__roplib_name):
        self.__lib_name = lib_name
        self.__rop_lib = cdll.LoadLibrary(self.__get_lib_path(self.__lib_name))
        if self.__rop_lib is None:
            raise Exception('Failed to load {}'.format(self.__lib_name))
        self.__ffi_funcs = {}
        set_conversion_mode(self.string8_format, 'strict')
        self.__retains = [{}, {}]

    def rnp_result_to_string(self, result):
        '''F(result: int) -> str
        '''
        rop_fx = self.__ffilib_function('rnp_result_to_string', lambda: CFUNCTYPE(c_char_p, c_uint))
        return rop_fx(result)

    def rnp_version_string(self):
        '''F() -> str
        '''
        rop_fx = self.__ffilib_function('rnp_version_string', lambda: CFUNCTYPE(c_char_p))
        return rop_fx()

    def rnp_version_string_full(self):
        '''F() -> str
        '''
        rop_fx = self.__ffilib_function('rnp_version_string_full', lambda: CFUNCTYPE(c_char_p))
        return rop_fx()

    def rnp_version(self):
        '''F() -> int / SCRWD_P
        '''
        rop_fx = self.__ffilib_function('rnp_version', lambda: CFUNCTYPE(c_uint))
        return rop_fx()

    def rnp_version_for(self, major, minor, patch):
        '''F(major: int, minor: int, patch: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_version_for', lambda: \
            CFUNCTYPE(c_uint, c_uint, c_uint, c_uint))
        return rop_fx(major, minor, patch)

    def rnp_version_major(self, version):
        '''F(version: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_version_major', lambda: CFUNCTYPE(c_uint, c_uint))
        return rop_fx(version)

    def rnp_version_minor(self, version):
        '''F(version: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_version_minor', lambda: CFUNCTYPE(c_uint, c_uint))
        return rop_fx(version)

    def rnp_version_patch(self, version):
        '''F(version: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_version_patch', lambda: CFUNCTYPE(c_uint, c_uint))
        return rop_fx(version)

    #
    def rnp_version_commit_timestamp(self):
        '''F() -> int
        '''
        rop_fx = self.__ffilib_function('rnp_version_commit_timestamp', lambda: \
            CFUNCTYPE(c_ulonglong))
        return rop_fx()

    def rnp_enable_debug(self, file):
        '''F(file: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_enable_debug', lambda: CFUNCTYPE(c_uint, c_char_p))
        return rop_fx(file)

    def rnp_disable_debug(self):
        '''F() -> int
        '''
        rop_fx = self.__ffilib_function('rnp_disable_debug', lambda: CFUNCTYPE(c_uint))
        return rop_fx()

    def rnp_ffi_create(self, ffi, pub_format, sec_format):
        '''F(ffi: [cd], pub_format: str, sec_format: str) -> int
        '''
        rparams = ((ffi, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_ffi_create', lambda: \
            CFUNCTYPE(c_uint, POINTER(c_void_p), c_char_p, c_char_p))
        ret = rop_fx(refs[0], pub_format, sec_format)
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_ffi_destroy(self, ffi):
        '''F(ffi: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_ffi_destroy', lambda: CFUNCTYPE(c_uint, c_void_p))
        self.__retains[0].pop(id(ffi), None)
        return rop_fx(ffi)

    def rnp_ffi_set_log_fd(self, ffi, fd_):
        '''F(ffi: cd, fd_: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_ffi_set_log_fd', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_int))
        return rop_fx(ffi, fd_)

    def rnp_ffi_set_key_provider(self, ffi, getkeycb, getkeycb_ctx):
        '''F(ffi: cd, getkeycb: Rop_get_key_cb, getkeycb_ctx: obj) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_ffi_set_key_provider', lambda: \
            CFUNCTYPE(c_uint, c_void_p, self.Rop_get_key_cb, py_object))
        return rop_fx(ffi, getkeycb, getkeycb_ctx)

    def rnp_ffi_set_pass_provider(self, ffi, getpasscb, getpasscb_ctx):
        '''F(ffi: cd, getpasscb: Rop_password_cb, getpasscb_ctx: obj) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_ffi_set_pass_provider', lambda: \
            CFUNCTYPE(c_uint, c_void_p, self.Rop_password_cb, py_object))
        self.__retains[0][id(ffi)] = getpasscb_ctx
        return rop_fx(ffi, getpasscb, getpasscb_ctx)

    def rnp_get_default_homedir(self, homedir):
        '''F(homedir: [cd]) -> int
        '''
        rparams = ((homedir, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_get_default_homedir', lambda: \
            CFUNCTYPE(c_uint, POINTER(c_void_p)))
        ret = rop_fx(refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_detect_homedir_info(self, homedir, pub_format, pub_path, sec_format, sec_path):
        '''F(homedir: str, pub_format: [cd], pub_path: [cd], sec_format: [cd],
        sec_path: [cd]) -> int
        '''
        rparams = ((pub_format, c_void_p(None)), (pub_path, c_void_p(None)), \
            (sec_format, c_void_p(None)), (sec_path, c_void_p(None)))
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_detect_homedir_info', lambda: \
            CFUNCTYPE(c_uint, c_char_p, POINTER(c_void_p), POINTER(c_void_p), \
            POINTER(c_void_p), POINTER(c_void_p)))
        ret = rop_fx(homedir, refs[0], refs[1], refs[2], refs[3])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_detect_key_format(self, buf, buf_len, format_):
        '''F(buf: str, buf_len: int, format_: [cd]) -> int
        '''
        rparams = ((format_, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_detect_key_format', lambda: \
            CFUNCTYPE(c_uint, c_char_p, c_size_t, POINTER(c_void_p)))
        ret = rop_fx(buf, buf_len, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_calculate_iterations(self, hash_, msec, iterations):
        '''F(hash_: str, msec: int, iterations: [int]) -> int
        '''
        rparams = ((iterations, c_size_t(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_calculate_iterations', lambda: \
            CFUNCTYPE(c_uint, c_char_p, c_size_t, POINTER(c_size_t)))
        ret = rop_fx(hash_, msec, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_supports_feature(self, type_, name, supported):
        '''F(type_: str, name: str, supported: [bool]) -> int
        '''
        rparams = ((supported, c_bool(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_supports_feature', lambda: \
            CFUNCTYPE(c_uint, c_char_p, c_char_p, POINTER(c_bool)))
        ret = rop_fx(type_, name, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_supported_features(self, type_, result):
        '''F(type_: str, result: [cd]) -> int
        '''
        rparams = ((result, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_supported_features', lambda: \
            CFUNCTYPE(c_uint, c_char_p, POINTER(c_void_p)))
        ret = rop_fx(type_, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_request_password(self, ffi, key, context, password):
        '''F(ffi: cd, key: cd, context: str, password: [cd]) -> int
        '''
        rparams = ((password, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_request_password', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_void_p, c_char_p, POINTER(c_void_p)))
        ret = rop_fx(ffi, key, context, refs[0]);
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_load_keys(self, ffi, format_, input_, flags):
        '''F(ffi: cd, format_: str, input_: cd, flags: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_load_keys', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p, c_void_p, c_uint))
        return rop_fx(ffi, format_, input_, flags)

    def rnp_unload_keys(self, ffi, flags):
        '''F(ffi: cd, flags: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_unload_keys', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_uint))
        return rop_fx(ffi, flags)

    def rnp_import_keys(self, ffi, input_, flags, results):
        '''F(ffi: cd, input_: cd, flags: int, results: [cd]) -> int
        '''
        rparams = ((results, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_import_keys', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_void_p, c_uint, POINTER(c_void_p)))
        ret = rop_fx(ffi, input_, flags, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_import_signatures(self, ffi, input_, flags, results):
        '''F(ffi: cd, input_: cd, flags: int, results: [cd]) -> int
        '''
        rparams = ((results, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_import_signatures', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_void_p, c_uint, POINTER(c_void_p)))
        ret = rop_fx(ffi, input_, flags, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_save_keys(self, ffi, format_, output, flags):
        '''F(ffi: cd, format_: str, output: cd, flags: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_save_keys', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p, c_void_p, c_uint))
        return rop_fx(ffi, format_, output, flags)

    def rnp_get_public_key_count(self, ffi, count):
        '''F(ffi: cd, count: [int]) -> int
        '''
        rparams = ((count, c_size_t(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_get_public_key_count', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_size_t)))
        ret = rop_fx(ffi, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_get_secret_key_count(self, ffi, count):
        '''F(ffi: cd, count: [int]) -> int
        '''
        rparams = ((count, c_size_t(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_get_secret_key_count', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_size_t)))
        ret = rop_fx(ffi, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_locate_key(self, ffi, identifier_type, identifier, key):
        '''F(ffi: cd, identifier_type: str, identifier: str, key: [cd]) -> int
        '''
        rparams = ((key, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_locate_key', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p, c_char_p, POINTER(c_void_p)))
        ret = rop_fx(ffi, identifier_type, identifier, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_key_handle_destroy(self, key):
        '''F(key: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_key_handle_destroy', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(key)

    def rnp_generate_key_json(self, ffi, json, results):
        '''F(ffi: cd, json: str, results: [cd]) -> int
        '''
        rparams = ((results, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_generate_key_json', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p, POINTER(c_void_p)))
        ret = rop_fx(ffi, json, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_generate_key_rsa(self, ffi, bits, subbits, userid, password, key):
        '''F(ffi: cd, bits: int, subbits: int, userid: str, password: str, key: [cd]) -> int
        '''
        rparams = ((key, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_generate_key_rsa', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_uint, c_uint, c_char_p, c_char_p, POINTER(c_void_p)))
        ret = rop_fx(ffi, bits, subbits, userid, password, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_generate_key_dsa_eg(self, ffi, bits, subbits, userid, password, key):
        '''F(ffi: cd, bits: int, subbits: int, userid: str, password: str, key: [cd]) -> int
        '''
        rparams = ((key, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_generate_key_dsa_eg', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_uint, c_uint, c_char_p, c_char_p, POINTER(c_void_p)))
        ret = rop_fx(ffi, bits, subbits, userid, password, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_generate_key_ec(self, ffi, curve, userid, password, key):
        '''F(ffi: cd, curve: str, userid: str, password: str, key: [cd]) -> int
        '''
        rparams = ((key, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_generate_key_ec', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p, c_char_p, c_char_p, POINTER(c_void_p)))
        ret = rop_fx(ffi, curve, userid, \
            password, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_generate_key_25519(self, ffi, userid, password, key):
        '''F(ffi: cd, userid: str, password: str, key: [cd]) -> int
        '''
        rparams = ((key, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_generate_key_25519', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p, c_char_p, POINTER(c_void_p)))
        ret = rop_fx(ffi, userid, password, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_generate_key_sm2(self, ffi, userid, password, key):
        '''F(ffi: cd, userid: str, password: str, key: [cd]) -> int
        '''
        rparams = ((key, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_generate_key_sm2', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p, c_char_p, POINTER(c_void_p)))
        ret = rop_fx(ffi, userid, password, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_generate_key_ex(self, ffi, key_alg, sub_alg, key_bits, sub_bits, \
        key_curve, sub_curve, userid, password, key):
        '''F(ffi: cd, key_alg: str, sub_alg: str, key_bits: int, sub_bits: int,
        key_curve: str, sub_curve: str, userid: str, password: str, key: [cd]) -> int
        '''
        rparams = ((key, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_generate_key_ex', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p, c_char_p, c_uint, c_uint, \
                c_char_p, c_char_p, c_char_p, c_char_p, POINTER(c_void_p)))
        ret = rop_fx(ffi, key_alg, sub_alg, key_bits, sub_bits, \
            key_curve, sub_curve, userid, \
                password, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_generate_create(self, op_, ffi, alg):
        '''F(op_: [cd], ffi: cd, alg: str) -> int
        '''
        rparams = ((op_, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_generate_create', lambda: \
            CFUNCTYPE(c_uint, POINTER(c_void_p), c_void_p, c_char_p))
        ret = rop_fx(refs[0], ffi, alg)
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_generate_subkey_create(self, op_, ffi, primary, alg):
        '''F(op_: [cd], ffi: cd, primary: cd, alg: str) -> int
        '''
        rparams = ((op_, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_generate_subkey_create', lambda: \
            CFUNCTYPE(c_uint, POINTER(c_void_p), c_void_p, c_void_p, c_char_p))
        ret = rop_fx(refs[0], ffi, primary, alg)
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_generate_set_bits(self, op_, bits):
        '''F(op_: cd, bits: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_set_bits', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_uint))
        return rop_fx(op_, bits)

    def rnp_op_generate_set_hash(self, op_, hash_):
        '''F(op_: cd, hash_: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_set_hash', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(op_, hash_)

    def rnp_op_generate_set_dsa_qbits(self, op_, qbits):
        '''F(op_: cd, qbits: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_set_dsa_qbits', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_uint))
        return rop_fx(op_, qbits)

    def rnp_op_generate_set_curve(self, op_, curve):
        '''F(op_: cd, curve: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_set_curve', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(op_, curve)

    def rnp_op_generate_set_protection_password(self, op_, password):
        '''F(op_: cd, password: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_set_protection_password', \
            lambda: CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(op_, password)

    def rnp_op_generate_set_request_password(self, op_, request):
        '''F(op_: cd, request: bool) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_set_request_password', \
            lambda: CFUNCTYPE(c_uint, c_void_p, c_bool))
        return rop_fx(op_, request)

    def rnp_op_generate_set_protection_cipher(self, op_, cipher):
        '''F(op_: cd, cipher: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_set_protection_cipher', \
            lambda: CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(op_, cipher)

    def rnp_op_generate_set_protection_hash(self, op_, hash_):
        '''F(op_: cd, hash_: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_set_protection_hash', \
            lambda: CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(op_, hash_)

    def rnp_op_generate_set_protection_mode(self, op_, mode):
        '''F(op_: cd, mode: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_set_protection_mode', \
            lambda: CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(op_, mode)

    def rnp_op_generate_set_protection_iterations(self, op_, iterations):
        '''F(op_: cd, iterations: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_set_protection_iterations', \
            lambda: CFUNCTYPE(c_uint, c_void_p, c_uint))
        return rop_fx(op_, iterations)

    def rnp_op_generate_add_usage(self, op_, usage):
        '''F(op_: cd, usage: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_add_usage', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(op_, usage)

    def rnp_op_generate_clear_usage(self, op_):
        '''F(op_: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_clear_usage', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(op_)

    def rnp_op_generate_set_userid(self, op_, userid):
        '''F(op_: cd, userid: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_set_userid', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(op_, userid)

    def rnp_op_generate_set_expiration(self, op_, expiration):
        '''F(op_: cd, expiration: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_set_expiration', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_uint))
        return rop_fx(op_, expiration)

    def rnp_op_generate_add_pref_hash(self, op_, hash_):
        '''F(op_: cd, hash_: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_add_pref_hash', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(op_, hash_)

    def rnp_op_generate_clear_pref_hashes(self, op_):
        '''F(op_: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_clear_pref_hashes', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(op_)

    def rnp_op_generate_add_pref_compression(self, op_, compression):
        '''F(op_: cd, compression: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_add_pref_compression', \
            lambda: CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(op_, compression)

    def rnp_op_generate_clear_pref_compression(self, op_):
        '''F(op_: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_clear_pref_compression', \
            lambda: CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(op_)

    def rnp_op_generate_add_pref_cipher(self, op_, cipher):
        '''F(op_: cd, cipher: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_add_pref_cipher', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(op_, cipher)

    def rnp_op_generate_clear_pref_ciphers(self, op_):
        '''F(op_: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_clear_pref_ciphers', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(op_)

    def rnp_op_generate_set_pref_keyserver(self, op_, keyserver):
        '''F(op_: cd, keyserver: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_set_pref_keyserver', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(op_, keyserver)

    def rnp_op_generate_execute(self, op_):
        '''F(op_: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_execute', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(op_)

    def rnp_op_generate_get_key(self, op_, handle):
        '''F(op_: cd, handle: [cd]) -> int
        '''
        rparams = ((handle, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_generate_get_key', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(op_, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_generate_destroy(self, op_):
        '''F(op_: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_generate_destroy', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(op_)

    def rnp_key_export(self, key, output, flags):
        '''F(key: cd, output: cd, flags: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_key_export', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_void_p, c_uint))
        return rop_fx(key, output, flags)

    def rnp_key_export_autocrypt(self, key, subkey, uid, output, flags):
        '''F(key: cd, subkey: cd, uid: str, output: cd, flags: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_key_export_autocrypt', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_void_p, c_char_p, c_void_p, c_uint))
        return rop_fx(key, subkey, uid, output, flags)

    def rnp_key_export_revocation(self, key, output, flags, hash_, code, reason):
        '''F(key: cd, output: cd, flags: int, hash: str, code: str, reason: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_key_export_revocation', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_void_p, c_uint, c_char_p, c_char_p, c_char_p))
        return rop_fx(key, output, flags, hash_, code, reason)
        
    def rnp_key_revoke(self, key, flags, hash_, code, reason):
        '''F(key: cd, flags: int, hash: str, code: str, reason: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_key_revoke', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_uint, c_char_p, c_char_p, c_char_p))
        return rop_fx(key, flags, hash_, code, reason)

    def rnp_key_remove(self, key, flags):
        '''F(key: cd, flags: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_key_remove', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_uint))
        return rop_fx(key, flags)

    def rnp_guess_contents(self, input_, contents):
        '''F(input_: cd, contents: [cd]) -> int
        '''
        rparams = ((contents, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_guess_contents', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(input_, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_enarmor(self, input_, output, type_):
        '''F(input_: cd, output: cd, type_: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_enarmor', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_void_p, c_char_p))
        return rop_fx(input_, output, type_)

    def rnp_dearmor(self, input_, output):
        '''F(input_: cd, output: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_dearmor', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_void_p))
        return rop_fx(input_, output)

    def rnp_key_get_primary_uid(self, key, uid):
        '''F(key: cd, uid: [cd]) -> int
        '''
        rparams = ((uid, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_primary_uid', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_key_get_uid_count(self, key, count):
        '''F(key: cd, count: [int]) -> int
        '''
        rparams = ((count, c_size_t(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_uid_count', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_size_t)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_get_uid_at(self, key, idx, uid):
        '''F(key: cd, idx: int, uid: [cd]) -> int
        '''
        rparams = ((uid, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_uid_at', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_size_t, POINTER(c_void_p)))
        ret = rop_fx(key, idx, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_key_get_uid_handle_at(self, key, idx, uid):
        '''F(key: cd, idx: int, uid: [cd]) -> int
        '''
        rparams = ((uid, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_uid_handle_at', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_size_t, POINTER(c_void_p)))
        ret = rop_fx(key, idx, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_uid_get_type(self, uid, type_):
        '''F(uid: cd, type: [int]) -> int
        '''
        rparams = ((type_, c_uint(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_uid_get_type', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_uint)))
        ret = rop_fx(uid, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_uid_get_data(self, uid, data, size_):
        '''F(uid: cd, data: [cd], size: [int]) -> int
        '''
        rparams = ((data, c_void_p(None)), (size_, c_size_t(0)))
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_uid_get_data', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p), POINTER(c_size_t)))
        ret = rop_fx(uid, refs[0], refs[1])
        refs[1] = refs[1].value
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_uid_is_primary(self, uid, primary):
        '''F(uid: cd, primary: [int]) -> int
        '''
        rparams = ((primary, c_bool(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_uid_is_primary', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_bool)))
        ret = rop_fx(uid, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_uid_is_valid(self, uid, valid):
        '''F(uid: cd, valid: [int]) -> int
        '''
        rparams = ((valid, c_bool(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_uid_is_valid', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_bool)))
        ret = rop_fx(uid, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_get_signature_count(self, key, count):
        '''F(key: cd, count: [int]) -> int
        '''
        rparams = ((count, c_size_t(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_signature_count', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_size_t)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_get_signature_at(self, key, idx, sig):
        '''F(key: cd, idx: int, sig: [cd]) -> int
        '''
        rparams = ((sig, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_signature_at', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_size_t, POINTER(c_void_p)))
        ret = rop_fx(key, idx, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_key_get_revocation_signature(self, key, sig):
        '''F(key: cd, sig: [cd]) -> int
        '''
        rparams = ((sig, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_revocation_signature', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_uid_get_signature_count(self, uid, count):
        '''F(uid: cd, count: [int]) -> int
        '''
        rparams = ((count, c_size_t(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_uid_get_signature_count', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_size_t)))
        ret = rop_fx(uid, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_uid_get_signature_at(self, uid, idx, sig):
        '''F(uid: cd, idx: int, sig: [cd]) -> int
        '''
        rparams = ((sig, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_uid_get_signature_at', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_size_t, POINTER(c_void_p)))
        ret = rop_fx(uid, idx, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_signature_get_type(self, sig, type_):
        '''F(uid: cd, sig: [cd]) -> int
        '''
        rparams = ((type_, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_signature_get_type', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(sig, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_signature_get_alg(self, sig, alg):
        '''F(sig: cd, alg: [cd]) -> int
        '''
        rparams = ((alg, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_signature_get_alg', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(sig, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_signature_get_hash_alg(self, sig, alg):
        '''F(sig: cd, alg: [cd]) -> int
        '''
        rparams = ((alg, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_signature_get_hash_alg', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(sig, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_signature_get_creation(self, sig, create):
        '''F(sig: cd, create: [int]) -> int
        '''
        rparams = ((create, c_uint(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_signature_get_creation', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_uint)))
        ret = rop_fx(sig, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_signature_get_keyid(self, sig, result):
        '''F(sig: cd, result: [cd]) -> int
        '''
        rparams = ((result, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_signature_get_keyid', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(sig, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_signature_get_signer(self, sig, key):
        '''F(sig: cd, key: [cd]) -> int
        '''
        rparams = ((key, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_signature_get_signer', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(sig, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret


    def rnp_signature_is_valid(self, sig, flags):
        '''F(sig: cd, flags: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_signature_is_valid', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_uint))
        return rop_fx(sig, flags)

    def rnp_signature_packet_to_json(self, sig, flags, json):
        '''F(sig: cd, flags: int, json: [cd]) -> int
        '''
        rparams = ((json, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_signature_packet_to_json', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_uint, POINTER(c_void_p)))
        ret = rop_fx(sig, flags, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_signature_handle_destroy(self, sig):
        '''F(sig: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_signature_handle_destroy', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(sig)

    def rnp_uid_is_revoked(self, uid, result):
        '''F(uid: cd, result: [bool]) -> int
        '''
        rparams = ((result, c_bool(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_uid_is_revoked', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_bool)))
        ret = rop_fx(uid, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_uid_get_revocation_signature(self, uid, sig):
        '''F(uid: cd, sig: [cd]) -> int
        '''
        rparams = ((sig, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_uid_get_revocation_signature', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(uid, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_uid_handle_destroy(self, uid):
        '''F(uid: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_uid_handle_destroy', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(uid)

    def rnp_key_get_subkey_count(self, key, count):
        '''F(key: cd, count: [int]) -> int
        '''
        rparams = ((count, c_size_t(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_subkey_count', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_size_t)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_get_subkey_at(self, key, idx, subkey):
        '''F(key: cd, idx: int, subkey: [cd]) -> int
        '''
        rparams = ((subkey, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_subkey_at', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_size_t, POINTER(c_void_p)))
        ret = rop_fx(key, idx, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_key_get_alg(self, key, alg):
        '''F(key: cd, alg: [cd]) -> int
        '''
        rparams = ((alg, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_alg', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_key_get_bits(self, key, bits):
        '''F(key: cd, bits: [int]) -> int
        '''
        rparams = ((bits, c_uint(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_bits', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_uint)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_get_dsa_qbits(self, key, qbits):
        '''F(key: cd, qbits: [int]) -> int
        '''
        rparams = ((qbits, c_uint(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_dsa_qbits', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_uint)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_get_curve(self, key, curve):
        '''F(key: cd, curve: [cd]) -> int
        '''
        rparams = ((curve, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_curve', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_key_add_uid(self, key, uid, hash_, expiration, key_flags, primary):
        '''F(key: cd, uid: str, hash_: str, expiration: int, key_flags: int,
        primary: bool) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_key_add_uid', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p, c_char_p, c_uint, c_ubyte, c_bool))
        return rop_fx(key, uid, hash_, expiration, key_flags, primary)

    def rnp_key_get_fprint(self, key, fprint):
        '''F(key: cd, fprint: [cd]) -> int
        '''
        rparams = ((fprint, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_fprint', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_key_get_keyid(self, key, keyid):
        '''F(key: cd, keyid: [cd]) -> int
        '''
        rparams = ((keyid, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_keyid', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_key_get_grip(self, key, grip):
        '''F(key: cd, grip: [cd]) -> int
        '''
        rparams = ((grip, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_grip', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_key_get_primary_grip(self, key, grip):
        '''F(key: cd, grip: [cd]) -> int
        '''
        rparams = ((grip, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_primary_grip', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_key_get_primary_fprint(self, key, fprint):
        '''F(key: cd, fprint: [cd]) -> int
        '''
        rparams = ((fprint, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_primary_fprint', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_key_allows_usage(self, key, usage, result):
        '''F(key: cd, usage: str, result: [bool]) -> int
        '''
        rparams = ((result, c_bool(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_allows_usage', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p, POINTER(c_bool)))
        ret = rop_fx(key, usage, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_get_creation(self, key, result):
        '''F(key: cd, result: [int]) -> int
        '''
        rparams = ((result, c_uint(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_creation', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_uint)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_get_expiration(self, key, result):
        '''F(key: cd, result: [int]) -> int
        '''
        rparams = ((result, c_uint(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_expiration', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_uint)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret
    
    def rnp_key_set_expiration(self, key, expiry):
        '''F(key: cd, expiry: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_key_set_expiration', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_uint))
        return rop_fx(key, expiry)

    def rnp_key_is_valid(self, key, result):
        '''F(key: cd, result: [bool]) -> int
        '''
        rparams = ((result, c_bool(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_is_valid', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_bool)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_valid_till(self, key, result):
        '''F(key: cd, result: [int]) -> int
        '''
        rparams = ((result, c_uint(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_valid_till', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_uint)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_is_revoked(self, key, result):
        '''F(key: cd, result: [bool]) -> int
        '''
        rparams = ((result, c_bool(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_is_revoked', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_bool)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_get_revocation_reason(self, key, result):
        '''F(key: cd, result: [cd]) -> int
        '''
        rparams = ((result, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_revocation_reason', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_key_is_superseded(self, key, result):
        '''F(key: cd, result: [bool]) -> int
        '''
        rparams = ((result, c_bool(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_is_superseded', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_bool)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_is_compromised(self, key, result):
        '''F(key: cd, result: [bool]) -> int
        '''
        rparams = ((result, c_bool(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_is_compromised', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_bool)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_is_retired(self, key, result):
        '''F(key: cd, result: [bool]) -> int
        '''
        rparams = ((result, c_bool(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_is_retired', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_bool)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_is_locked(self, key, result):
        '''F(key: cd, result: [bool]) -> int
        '''
        rparams = ((result, c_bool(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_is_locked', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_bool)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_get_protection_type(self, key, type_):
        '''F(key: cd, type: [str]) -> int
        '''
        rparams = ((type_, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_protection_type', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_key_get_protection_mode(self, key, mode):
        '''F(key: cd, type: [str]) -> int
        '''
        rparams = ((mode, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_protection_mode', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_key_get_protection_cipher(self, key, cipher):
        '''F(key: cd, type: [str]) -> int
        '''
        rparams = ((cipher, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_protection_cipher', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_key_get_protection_hash(self, key, hash_):
        '''F(key: cd, type: [str]) -> int
        '''
        rparams = ((hash_, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_protection_hash', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_key_get_protection_iterations(self, key, iterations):
        '''F(key: cd, type: [int]) -> int
        '''
        rparams = ((iterations, c_size_t(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_get_protection_iterations', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_size_t)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_lock(self, key):
        '''F(key: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_key_lock', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(key)

    def rnp_key_unlock(self, key, password):
        '''F(key: cd, password: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_key_unlock', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(key, password)

    def rnp_key_is_protected(self, key, result):
        '''F(key: cd, result: [bool]) -> int
        '''
        rparams = ((result, c_bool(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_is_protected', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_bool)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_protect(self, handle, password, cipher, cipher_mode, hash_, iterations):
        '''F(handle: cd, password: str, cipher: str, cipher_mode: str, hash_:
        str, iterations: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_key_protect', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p, c_char_p, c_char_p, c_char_p, c_size_t))
        return rop_fx(handle, password, cipher, \
            cipher_mode, hash_, iterations)

    def rnp_key_unprotect(self, key, password):
        '''F(key: cd, password: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_key_unprotect', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(key, password)

    def rnp_key_is_primary(self, key, result):
        '''F(key: cd, result: [bool]) -> int
        '''
        rparams = ((result, c_bool(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_is_primary', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_bool)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_is_sub(self, key, result):
        '''F(key: cd, result: [bool]) -> int
        '''
        rparams = ((result, c_bool(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_is_sub', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_bool)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_have_secret(self, key, result):
        '''F(key: cd, result: [bool]) -> int
        '''
        rparams = ((result, c_bool(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_have_secret', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_bool)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_have_public(self, key, result):
        '''F(key: cd, result: [bool]) -> int
        '''
        rparams = ((result, c_bool(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_have_public', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_bool)))
        ret = rop_fx(key, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_key_packets_to_json(self, key, secret, flags, result):
        '''F(key: cd, secret: bool, flags: int, result: [cd]) -> int
        '''
        rparams = ((result, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_packets_to_json', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_bool, c_uint, POINTER(c_void_p)))
        ret = rop_fx(key, secret, flags, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_dump_packets_to_json(self, input_, flags, result):
        '''F(input_: cd, flags: int, result: [cd]) -> int
        '''
        rparams = ((result, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_dump_packets_to_json', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_uint, POINTER(c_void_p)))
        ret = rop_fx(input_, flags, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_dump_packets_to_output(self, input_, output, flags):
        '''F(input_: cd, output: cd, flags: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_dump_packets_to_output', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_void_p, c_uint))
        return rop_fx(input_, output, flags)

    def rnp_op_sign_create(self, op_, ffi, input_, output):
        '''F(op_: [cd], ffi: cd, input_: cd, output: cd) -> int
        '''
        rparams = ((op_, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_sign_create', lambda: \
            CFUNCTYPE(c_uint, POINTER(c_void_p), c_void_p, c_void_p, c_void_p))
        ret = rop_fx(refs[0], ffi, input_, output)
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_sign_cleartext_create(self, op_, ffi, input_, output):
        '''F(op_: [cd], ffi: cd, input_: cd, output: cd) -> int
        '''
        rparams = ((op_, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_sign_cleartext_create', lambda: \
            CFUNCTYPE(c_uint, POINTER(c_void_p), c_void_p, c_void_p, c_void_p))
        ret = rop_fx(refs[0], ffi, input_, output)
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_sign_detached_create(self, op_, ffi, input_, signature):
        '''F(op_: [cd], ffi: cd, input_: cd, signature: cd) -> int
        '''
        rparams = ((op_, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_sign_detached_create', lambda: \
            CFUNCTYPE(c_uint, POINTER(c_void_p), c_void_p, c_void_p, c_void_p))
        ret = rop_fx(refs[0], ffi, input_, signature)
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_sign_add_signature(self, op_, key, sig):
        '''F(op_: cd, key: cd, sig: [cd]) -> int
        '''
        rparams = ((sig, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_sign_add_signature', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(op_, key, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_sign_signature_set_hash(self, sig, hash_):
        '''F(sig: cd, hash_: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_sign_signature_set_hash', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(sig, hash_)

    def rnp_op_sign_signature_set_creation_time(self, sig, create):
        '''F(sig: cd, create: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_sign_signature_set_creation_time', \
            lambda: CFUNCTYPE(c_uint, c_void_p, c_uint))
        return rop_fx(sig, create)

    def rnp_op_sign_signature_set_expiration_time(self, sig, expires):
        '''F(sig: cd, expires: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_sign_signature_set_expiration_time', \
            lambda: CFUNCTYPE(c_uint, c_void_p, c_uint))
        return rop_fx(sig, expires)

    def rnp_op_sign_set_compression(self, op_, compression, level):
        '''F(op_: cd, compression: str, level: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_sign_set_compression', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p, c_int))
        return rop_fx(op_, compression, level)

    def rnp_op_sign_set_armor(self, op_, armored):
        '''F(op_: cd, armored: bool) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_sign_set_armor', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_bool))
        return rop_fx(op_, armored)

    def rnp_op_sign_set_hash(self, op_, hash_):
        '''F(op_: cd, hash_: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_sign_set_hash', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(op_, hash_)

    def rnp_op_sign_set_creation_time(self, op_, create):
        '''F(op_: cd, create: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_sign_set_creation_time', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_uint))
        return rop_fx(op_, create)

    def rnp_op_sign_set_expiration_time(self, op_, expire):
        '''F(op_: cd, expire: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_sign_set_expiration_time', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_uint))
        return rop_fx(op_, expire)

    def rnp_op_sign_set_file_name(self, op_, filename):
        '''F(op_: cd, filename: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_sign_set_file_name', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(op_, filename)

    def rnp_op_sign_set_file_mtime(self, op_, mtime):
        '''F(op_: cd, mtime: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_sign_set_file_mtime', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_uint))
        return rop_fx(op_, mtime)

    def rnp_op_sign_execute(self, op_):
        '''F(op_: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_sign_execute', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(op_)

    def rnp_op_sign_destroy(self, op_):
        '''F(op_: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_sign_destroy', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(op_)

    def rnp_op_verify_create(self, op_, ffi, input_, output):
        '''F(op_: [cd], ffi: cd, input_: cd, output: cd) -> int
        '''
        rparams = ((op_, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_verify_create', lambda: \
            CFUNCTYPE(c_uint, POINTER(c_void_p), c_void_p, c_void_p, c_void_p))
        ret = rop_fx(refs[0], ffi, input_, output)
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_verify_detached_create(self, op_, ffi, input_, signature):
        '''F(op_: [cd], ffi: cd, input_: cd, signature: cd) -> int
        '''
        rparams = ((op_, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_verify_detached_create', lambda: \
            CFUNCTYPE(c_uint, POINTER(c_void_p), c_void_p, c_void_p, c_void_p))
        ret = rop_fx(refs[0], ffi, input_, signature)
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_verify_execute(self, op_):
        '''F(op_: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_verify_execute', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(op_)

    def rnp_op_verify_get_signature_count(self, op_, count):
        '''F(op_: cd, count: [int]) -> int
        '''
        rparams = ((count, c_size_t(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_verify_get_signature_count', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_size_t)))
        ret = rop_fx(op_, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_op_verify_get_signature_at(self, op_, idx, sig):
        '''F(op_: cd, idx: int, sig: [cd]) -> int
        '''
        rparams = ((sig, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_verify_get_signature_at', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_size_t, POINTER(c_void_p)))
        ret = rop_fx(op_, idx, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_verify_get_file_info(self, op_, filename, mtime):
        '''F(op_: cd, filename: [cd], mtime: [int]) -> int
        '''
        rparams = ((filename, c_void_p(None)), (mtime, c_uint(0)))
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_verify_get_file_info', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p), POINTER(c_uint)))
        ret = rop_fx(op_, refs[0], refs[1])
        refs[1] = refs[1].value
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_verify_get_protection_info(self, op_, mode, cipher, valid):
        '''F(op: cd, mode: [str], cipher: [str], valid: [bool]) -> int
        '''
        rparams = ((mode, c_void_p(None)), (cipher, c_void_p(None)), (valid, c_bool(False)))
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_verify_get_protection_info', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p), POINTER(c_void_p), POINTER(c_bool)))
        ret = rop_fx(op_, refs[0], refs[1], refs[2])
        refs[2] = refs[2].value
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_verify_get_recipient_count(self, op_, count):
        '''F(op: cd, count: [int]) -> int
        '''
        rparams = ((count, c_size_t(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_verify_get_recipient_count', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_size_t)))
        ret = rop_fx(op_, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_op_verify_get_used_recipient(self, op_, recipient):
        '''F(op: cd, recipient: [cd]) -> int
        '''
        rparams = ((recipient, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_verify_get_used_recipient', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(op_, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_verify_get_recipient_at(self, op_, idx, recipient):
        '''F(op: cd, idx: int, recipient: [cd]) -> int
        '''
        rparams = ((recipient, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_verify_get_recipient_at', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_size_t, POINTER(c_void_p)))
        ret = rop_fx(op_, idx, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_verify_get_symenc_count(self, op_, count):
        '''F(op: cd, count: [int]) -> int
        '''
        rparams = ((count, c_size_t(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_verify_get_symenc_count', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_size_t)))
        ret = rop_fx(op_, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_op_verify_get_used_symenc(self, op_, symenc):
        '''F(op: cd, symenc: [cd]) -> int
        '''
        rparams = ((symenc, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_verify_get_used_symenc', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(op_, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_verify_get_symenc_at(self, op_, idx, symenc):
        '''F(op: cd, idx: int, symenc: [cd]) -> int
        '''
        rparams = ((symenc, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_verify_get_symenc_at', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_size_t, POINTER(c_void_p)))
        ret = rop_fx(op_, idx, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_recipient_get_keyid(self, recipient, keyid):
        '''F(recipient: cd, keyid: [str]) -> int
        '''
        rparams = ((keyid, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_recipient_get_keyid', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(recipient, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_recipient_get_alg(self, recipient, alg):
        '''F(recipient: cd, alg: [str]) -> int
        '''
        rparams = ((alg, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_recipient_get_alg', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(recipient, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_symenc_get_cipher(self, symenc, cipher):
        '''F(symenc: cd, cipher: [str]) -> int
        '''
        rparams = ((cipher, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_symenc_get_cipher', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(symenc, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_symenc_get_aead_alg(self, symenc, alg):
        '''F(symenc: cd, alg: [str]) -> int
        '''
        rparams = ((alg, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_symenc_get_aead_alg', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(symenc, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_symenc_get_hash_alg(self, symenc, alg):
        '''F(symenc: cd, alg: [str]) -> int
        '''
        rparams = ((alg, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_symenc_get_hash_alg', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(symenc, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_symenc_get_s2k_type(self, symenc, type_):
        '''F(symenc: cd, type: [str]) -> int
        '''
        rparams = ((type_, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_symenc_get_s2k_type', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(symenc, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_symenc_get_s2k_iterations(self, symenc, iterations):
        '''F(symenc: cd, iterations: [int]) -> int
        '''
        rparams = ((iterations, c_size_t(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_symenc_get_s2k_iterations', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_size_t)))
        ret = rop_fx(symenc, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_op_verify_destroy(self, op_):
        '''F(op_: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_verify_destroy', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(op_)

    def rnp_op_verify_signature_get_status(self, sig):
        '''F(sig: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_verify_signature_get_status', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(sig)

    def rnp_op_verify_signature_get_handle(self, sig, handle):
        '''F(sig: cd, handle: [cd]) -> int
        '''
        rparams = ((handle, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_verify_signature_get_handle', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(sig, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_verify_signature_get_hash(self, sig, hash_):
        '''F(sig: cd, hash_: [cd]) -> int
        '''
        rparams = ((hash_, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_verify_signature_get_hash', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(sig, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_verify_signature_get_key(self, sig, key):
        '''F(sig: cd, key: [cd]) -> int
        '''
        rparams = ((key, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_verify_signature_get_key', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(sig, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_verify_signature_get_times(self, sig, create, expires):
        '''F(sig: cd, create: [int], expires: [int]) -> int
        '''
        rparams = ((create, c_uint(0)), (expires, c_uint(0)))
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_verify_signature_get_times', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_uint), POINTER(c_uint)))
        ret = rop_fx(sig, refs[0], refs[1])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_buffer_destroy(self, ptr):
        '''F(ptr: cd)
        '''
        rop_fx = self.__ffilib_function('rnp_buffer_destroy', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        rop_fx(ptr)

    def rnp_buffer_clear(self, ptr, size_):
        '''F(ptr: cd, int)
        '''
        rop_fx = self.__ffilib_function('rnp_buffer_clear', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_size_t))
        rop_fx(ptr, size_)

    def rnp_input_from_path(self, input_, path):
        '''F(input_: [cd], path: str) -> int
        '''
        rparams = ((input_, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_input_from_path', lambda: \
            CFUNCTYPE(c_uint, POINTER(c_void_p), c_char_p))
        ret = rop_fx(refs[0], path)
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_input_from_memory(self, input_, buf, buf_len, do_copy):
        '''F(input_: [cd], buf: bstr, buf_len: int, do_copy: bool) -> int
        '''
        rparams = ((input_, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_input_from_memory', lambda: \
            CFUNCTYPE(c_uint, POINTER(c_void_p), c_void_p, c_size_t, c_bool))
        ret = rop_fx(refs[0], buf, buf_len, do_copy)
        if refs[0] is not None:
            self.__retains[1][id(refs[0])] = buf
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_input_from_callback(self, input_, reader, closer, app_ctx):
        '''F(input_: [cd], reader: Rop_input_reader_t, closer: Rop_input_closer_t,
        app_ctx: obj) -> int
        '''
        rparams = ((input_, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_input_from_callback', lambda: \
            CFUNCTYPE(c_uint, POINTER(c_void_p), self.Rop_input_reader_t, \
                self.Rop_input_closer_t, py_object))
        ret = rop_fx(refs[0], reader, closer, app_ctx)
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_input_destroy(self, input_):
        '''F(input_: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_input_destroy', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        self.__retains[1].pop(id(input_), None)
        return rop_fx(input_)

    def rnp_output_to_path(self, output, path):
        '''F(output: [cd], path: str) -> int
        '''
        rparams = ((output, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_output_to_path', lambda: \
            CFUNCTYPE(c_uint, POINTER(c_void_p), c_char_p))
        ret = rop_fx(refs[0], path)
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_output_to_file(self, output, path, flags):
        '''F(output: [cd], path: str, flags: int) -> int
        '''
        rparams = ((output, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_output_to_file', lambda: \
            CFUNCTYPE(c_uint, POINTER(c_void_p), c_char_p, c_uint))
        ret = rop_fx(refs[0], path, flags)
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_output_to_memory(self, output, max_alloc):
        '''F(output: [cd], max_alloc: int) -> int
        '''
        rparams = ((output, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_output_to_memory', lambda: \
            CFUNCTYPE(c_uint, POINTER(c_void_p), c_size_t))
        ret = rop_fx(refs[0], max_alloc)
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_output_to_armor(self, base, output, type_):
        '''F(base: cd, output: [cd], type_: str) -> int
        '''
        rparams = ((output, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_output_to_armor', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p), c_char_p))
        ret = rop_fx(base, refs[0], type_)
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_output_memory_get_buf(self, output, buf, len_, do_copy):
        '''F(output: cd, buf: [cd], len_: [int], do_copy: bool) -> int
        '''
        rparams = ((buf, c_void_p(None)), (len_, c_size_t(0)))
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_output_memory_get_buf', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p), POINTER(c_size_t), c_bool))
        ret = rop_fx(output, refs[0], refs[1], do_copy)
        refs[1] = refs[1].value
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_output_to_callback(self, output, writer, closer, app_ctx):
        '''F(output: [cd], writer: Rop_output_writer_t, closer: Rop_output_closer_t,
        app_ctx: obj) -> int
        '''
        rparams = ((output, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_output_to_callback', lambda: \
            CFUNCTYPE(c_uint, POINTER(c_void_p), self.Rop_output_writer_t, \
                self.Rop_output_closer_t, c_void_p))
        ret = rop_fx(refs[0], writer, closer, app_ctx)
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_output_to_null(self, output):
        '''F(output: [cd]) -> int
        '''
        rparams = ((output, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_output_to_null', lambda: \
            CFUNCTYPE(c_uint, POINTER(c_void_p)))
        ret = rop_fx(refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_output_write(self, output, data, size, written):
        '''F(output: cd, data: obj, size: int, written: [int]) -> int
        '''
        rparams = ((written, c_size_t(0)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_output_write', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_void_p, c_size_t, POINTER(c_size_t)))
        ret = rop_fx(output, data, size, refs[0])
        self.__refs_final(refs, rparams)
        return ret

    def rnp_output_finish(self, output):
        '''F(output: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_output_finish', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(output)

    def rnp_output_destroy(self, output):
        '''F(output: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_output_destroy', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(output)

    def rnp_op_encrypt_create(self, op_, ffi, input_, output):
        '''F(op_: [cd], ffi: cd, input_: cd, output: cd) -> int
        '''
        rparams = ((op_, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_encrypt_create', lambda: \
            CFUNCTYPE(c_uint, POINTER(c_void_p), c_void_p, c_void_p, c_void_p))
        ret = rop_fx(refs[0], ffi, input_, output)
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_encrypt_add_recipient(self, op_, key):
        '''F(op_: cd, key: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_encrypt_add_recipient', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_void_p))
        return rop_fx(op_, key)

    def rnp_op_encrypt_add_signature(self, op_, key, sig):
        '''F(op_: cd, key: cd, sig: [cd]) -> int
        '''
        rparams = ((sig, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_op_encrypt_add_signature', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(op_, key, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_op_encrypt_set_hash(self, op_, hash_):
        '''F(op_: cd, hash_: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_encrypt_set_hash', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(op_, hash_)

    def rnp_op_encrypt_set_creation_time(self, op_, create):
        '''F(op_: cd, create: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_encrypt_set_creation_time', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_uint))
        return rop_fx(op_, create)

    def rnp_op_encrypt_set_expiration_time(self, op_, expire):
        '''F(op_: cd, expire: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_encrypt_set_expiration_time', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_uint))
        return rop_fx(op_, expire)

    def rnp_op_encrypt_add_password(self, op_, password, s2k_hash, iterations, s2k_cipher):
        '''F(op_: cd, password: str, s2k_hash: str, iterations: int,
        s2k_cipher: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_encrypt_add_password', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p, c_char_p, c_size_t, c_char_p))
        return rop_fx(op_, password, s2k_hash, iterations, \
            s2k_cipher)

    def rnp_op_encrypt_set_armor(self, op_, armored):
        '''F(op_: cd, armored: bool) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_encrypt_set_armor', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_bool))
        return rop_fx(op_, armored)

    def rnp_op_encrypt_set_cipher(self, op_, cipher):
        '''F(op_: cd, cipher: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_encrypt_set_cipher', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(op_, cipher)

    def rnp_op_encrypt_set_aead(self, op_, alg):
        '''F(op_: cd, alg: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_encrypt_set_aead', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(op_, alg)

    def rnp_op_encrypt_set_aead_bits(self, op_, bits):
        '''F(op_: cd, bits: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_encrypt_set_aead_bits', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_int))
        return rop_fx(op_, bits)

    def rnp_op_encrypt_set_compression(self, op_, compression, level):
        '''F(op_: cd, compression str, level: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_encrypt_set_compression', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p, c_int))
        return rop_fx(op_, compression, level)

    def rnp_op_encrypt_set_file_name(self, op_, filename):
        '''F(op_: cd, filename: str) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_encrypt_set_file_name', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_char_p))
        return rop_fx(op_, filename)

    def rnp_op_encrypt_set_file_mtime(self, op_, mtime):
        '''F(op_: cd, mtime: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_encrypt_set_file_mtime', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_uint))
        return rop_fx(op_, mtime)

    def rnp_op_encrypt_execute(self, op_):
        '''F(op_: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_encrypt_execute', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(op_)

    def rnp_op_encrypt_destroy(self, op_):
        '''F(op_: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_op_encrypt_destroy', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(op_)

    def rnp_decrypt(self, ffi, input_, output):
        '''F(ffi: cd, input_: cd, output: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_decrypt', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_void_p, c_void_p))
        return rop_fx(ffi, input_, output)

    def rnp_get_public_key_data(self, handle, buf, buf_len):
        '''F(handle: cd, buf: [cd], buf_len: [int]) -> int
        '''
        rparams = ((buf, c_void_p(None)), (buf_len, c_size_t(0)))
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_get_public_key_data', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p), POINTER(c_size_t)))
        ret = rop_fx(handle, refs[0], refs[1])
        refs[1] = refs[1].value
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_get_secret_key_data(self, handle, buf, buf_len):
        '''F(handle: cd, buf: [cd], buf_len: [int]) -> int
        '''
        rparams = ((buf, c_void_p(None)), (buf_len, c_size_t(0)))
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_get_secret_key_data', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p), POINTER(c_size_t)))
        ret = rop_fx(handle, refs[0], refs[1])
        refs[1] = refs[1].value
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_key_to_json(self, handle, flags, result):
        '''F(handle: cd, flags: int, result: [cd]) -> int
        '''
        rparams = ((result, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_key_to_json', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_uint, POINTER(c_void_p)))
        ret = rop_fx(handle, flags, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_identifier_iterator_create(self, ffi, it_, identifier_type):
        '''F(ffi: cd, it_: [cd], identifier_type: str) -> int
        '''
        rparams = ((it_, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_identifier_iterator_create', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p), c_char_p))
        ret = rop_fx(ffi, refs[0], identifier_type)
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_identifier_iterator_next(self, it_, identifier):
        '''F(it_: cd, identifier: [cd]) -> int
        '''
        rparams = ((identifier, c_void_p(None)),)
        refs = self.__refs_init(rparams)
        rop_fx = self.__ffilib_function('rnp_identifier_iterator_next', lambda: \
            CFUNCTYPE(c_uint, c_void_p, POINTER(c_void_p)))
        ret = rop_fx(it_, refs[0])
        self.__refs_final(refs, rparams, ref_get=None)
        return ret

    def rnp_identifier_iterator_destroy(self, it_):
        '''F(it_: cd) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_identifier_iterator_destroy', lambda: \
            CFUNCTYPE(c_uint, c_void_p))
        return rop_fx(it_)

    def rnp_output_pipe(self, input_, output):
        '''F(input: cd, output: [cd]) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_output_pipe', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_void_p))
        return rop_fx(input_, output)

    def rnp_output_armor_set_line_length(self, output, len_):
        '''F(output: cd, llen: int) -> int
        '''
        rop_fx = self.__ffilib_function('rnp_output_armor_set_line_length', lambda: \
            CFUNCTYPE(c_uint, c_void_p, c_size_t))
        return rop_fx(output, len_)

    def __ffilib_function(self, fx_name, fx_type):
        ffi_fx = self.__ffi_funcs.get(fx_name)
        if ffi_fx is None:
            #ffi_symb = 'ffib_p_' + fx_name
            ffi_symb = fx_name
            ffi_fx = c_void_p.in_dll(self.__rop_lib, ffi_symb)
            ffi_fx = fx_type()(addressof(ffi_fx))
            if ffi_fx is not None:
                self.__ffi_funcs[fx_name] = ffi_fx
            else:
                raise Exception('Missing symbol {} in {}'.format(ffi_symb, \
                    self.__lib_name))
        return ffi_fx

    def __get_lib_path(self, lib_name):
        path = find_library(lib_name)
        if path is None:
            path = find_library('lib{}'.format(lib_name))
        if path is None:
            path = 'lib{}.so'.format(lib_name)
        return path

    @property
    def retains(self): return self.__retains

    @staticmethod
    def __refs_init(vars_):
        refs = [None] * len(vars_)
        for idx, svar in enumerate(vars_):
            if svar[0] is not None:
                refs[idx] = svar[1]
        return refs

    @staticmethod
    def __refs_final(refs, vars_, ref_get=lambda x: x.value, append=True):
        for idx, svar in enumerate(vars_):
            svar0 = svar[0]
            if svar0 is not None:
                if not append:
                    del svar0[:]
                svar0.append(ref_get(refs[idx]) if ref_get is not None else refs[idx])


class RopLibDef(object):
    '''Flags
    '''
    @property
    def RNP_KEY_EXPORT_ARMORED(self): return (1 << 0)
    @property
    def RNP_KEY_EXPORT_PUBLIC(self): return (1 << 1)
    @property
    def RNP_KEY_EXPORT_SECRET(self): return (1 << 2)
    @property
    def RNP_KEY_EXPORT_SUBKEYS(self): return (1 << 3)

    @property
    def RNP_KEY_REMOVE_PUBLIC(self): return (1 << 0)
    @property
    def RNP_KEY_REMOVE_SECRET(self): return (1 << 1)
    @property
    def RNP_KEY_REMOVE_SUBKEYS(self): return (1 << 2)

    @property
    def RNP_KEY_UNLOAD_PUBLIC(self): return (1 << 0)
    @property
    def RNP_KEY_UNLOAD_SECRET(self): return (1 << 1)

    # Flags for optional details to include in JSON.
    @property
    def RNP_JSON_PUBLIC_MPIS(self): return (1 << 0)
    @property
    def RNP_JSON_SECRET_MPIS(self): return (1 << 1)
    @property
    def RNP_JSON_SIGNATURES(self): return (1 << 2)
    @property
    def RNP_JSON_SIGNATURE_MPIS(self): return (1 << 3)

    # Flags to include additional data in packet dumping
    @property
    def RNP_JSON_DUMP_MPI(self): return (1 << 0)
    @property
    def RNP_JSON_DUMP_RAW(self): return (1 << 1)
    @property
    def RNP_JSON_DUMP_GRIP(self): return (1 << 2)

    @property
    def RNP_DUMP_MPI(self): return (1 << 0)
    @property
    def RNP_DUMP_RAW(self): return (1 << 1)
    @property
    def RNP_DUMP_GRIP(self): return (1 << 2)

    # Flags for the key loading/saving functions.
    @property
    def RNP_LOAD_SAVE_PUBLIC_KEYS(self): return (1 << 0)
    @property
    def RNP_LOAD_SAVE_SECRET_KEYS(self): return (1 << 1)
    @property
    def RNP_LOAD_SAVE_PERMISSIVE(self): return (1 << 8)
    @property
    def RNP_LOAD_SAVE_SINGLE(self): return (1 << 9)

    # Flags for output structure creation.
    @property
    def RNP_OUTPUT_FILE_OVERWRITE(self): return (1 << 0)
    @property
    def RNP_OUTPUT_FILE_RANDOM(self): return (1 << 1)

    # User id type
    @property
    def RNP_USER_ID(self): return 1
    @property
    def RNP_USER_ATTR(self): return 2

    # Algorithm Strings
    @property
    def RNP_ALGNAME_PLAINTEXT(self): return "PLAINTEXT"
    @property
    def RNP_ALGNAME_RSA(self): return "RSA"
    @property
    def RNP_ALGNAME_ELGAMAL(self): return "ELGAMAL"
    @property
    def RNP_ALGNAME_DSA(self): return "DSA"
    @property
    def RNP_ALGNAME_ECDH(self): return "ECDH"
    @property
    def RNP_ALGNAME_ECDSA(self): return "ECDSA"
    @property
    def RNP_ALGNAME_EDDSA(self): return "EDDSA"
    @property
    def RNP_ALGNAME_IDEA(self): return "IDEA"
    @property
    def RNP_ALGNAME_TRIPLEDES(self): return "TRIPLEDES"
    @property
    def RNP_ALGNAME_CAST5(self): return "CAST5"
    @property
    def RNP_ALGNAME_BLOWFISH(self): return "BLOWFISH"
    @property
    def RNP_ALGNAME_TWOFISH(self): return "TWOFISH"
    @property
    def RNP_ALGNAME_AES_128(self): return "AES128"
    @property
    def RNP_ALGNAME_AES_192(self): return "AES192"
    @property
    def RNP_ALGNAME_AES_256(self): return "AES256"
    @property
    def RNP_ALGNAME_CAMELLIA_128(self): return "CAMELLIA128"
    @property
    def RNP_ALGNAME_CAMELLIA_192(self): return "CAMELLIA192"
    @property
    def RNP_ALGNAME_CAMELLIA_256(self): return "CAMELLIA256"
    @property
    def RNP_ALGNAME_SM2(self): return "SM2"
    @property
    def RNP_ALGNAME_SM3(self): return "SM3"
    @property
    def RNP_ALGNAME_SM4(self): return "SM4"
    @property
    def RNP_ALGNAME_MD5(self): return "MD5"
    @property
    def RNP_ALGNAME_SHA1(self): return "SHA1"
    @property
    def RNP_ALGNAME_SHA256(self): return "SHA256"
    @property
    def RNP_ALGNAME_SHA384(self): return "SHA384"
    @property
    def RNP_ALGNAME_SHA512(self): return "SHA512"
    @property
    def RNP_ALGNAME_SHA224(self): return "SHA224"
    @property
    def RNP_ALGNAME_SHA3_256(self): return "SHA3-256"
    @property
    def RNP_ALGNAME_SHA3_512(self): return "SHA3-512"
    @property
    def RNP_ALGNAME_RIPEMD160(self): return "RIPEMD160"
    @property
    def RNP_ALGNAME_CRC24(self): return "CRC24"

    # SHA1 is not considered secured anymore and SHOULD NOT be used to create messages (as per
    # Appendix C of RFC 4880-bis-02). SHA2 MUST be implemented.
    # Let's pre-empt this by specifying SHA256 - gpg interoperates just fine with SHA256 - agc,
    # 20090522
    @property
    def DEFAULT_HASH_ALG(self): return RNP_ALGNAME_SHA256

    # Default symmetric algorithm
    @property
    def DEFAULT_SYMM_ALG(self): return RNP_ALGNAME_AES_256

    # Keystore format: GPG, KBX (pub), G10 (sec), GPG21 ( KBX for pub, G10 for sec)
    @property
    def RNP_KEYSTORE_GPG(self): return "GPG"
    @property
    def RNP_KEYSTORE_KBX(self): return "KBX"
    @property
    def RNP_KEYSTORE_G10(self): return "G10"
    @property
    def RNP_KEYSTORE_GPG21(self): return "GPG21"


class PyRopUtils(object):
    '''Handy fuctions
    '''
    @staticmethod
    def read_memory(ptr, length):
        buf = create_string_buffer(length)
        memmove(buf, ptr, length)
        return bytes(buf.raw)

    @staticmethod
    def write_memory(dst, dst_len, src):
        return memmove(dst, c_char_p(src), min(dst_len, len(src)))

    @staticmethod
    def write_string8(dst, dst_len, src):
        return PyRopUtils.write_memory(dst, dst_len, src.encode(RopLib.string8_format)+b'\0')

    @staticmethod
    # to bool(?, string, ?, string, int)
    def reshape_password_cb(function):
        def cb_wrap(ffi, app_ctx, key, pgp_context, buf, buf_len):
            ret, ret_buf = function(ffi, app_ctx, key, pgp_context \
                    if pgp_context is not None else None, buf_len)
            if ret_buf is not None:
                PyRopUtils.write_string8(buf, buf_len, ret_buf)
            return ret
        return cb_wrap

    @staticmethod
    # to bool(?, list, int, int*)
    def reshape_reader_cb(function):
        def cb_wrap(app_ctx, buf, buf_len, read_):
            ret_buf = function(app_ctx, buf_len)
            if ret_buf is not None:
                PyRopUtils.write_memory(buf, buf_len, ret_buf)
                memmove(read_, byref(c_size_t(len(ret_buf) if ret_buf is not None else 0)), sizeof(c_size_t))
                return True
            return False
        return cb_wrap

    @staticmethod
    # to None(?)
    def reshape_rcloser_cb(function):
        def cb_wrap(app_ctx):
            function(app_ctx.value if app_ctx is not None else None)
            return 0
        return cb_wrap

    @staticmethod
    # to bool(?, bytes)
    def reshape_writer_cb(function):
        def cb_wrap(app_ctx, buf, buf_len):
            return function(app_ctx.value if app_ctx is not None else None, \
                PyRopUtils.read_memory(buf, buf_len))
        return cb_wrap

    @staticmethod
    # to None(?, bool)
    def reshape_wcloser_cb(function):
        def cb_wrap(app_ctx, discard):
            function(app_ctx.value if app_ctx is not None else None, discard)
            return 0
        return cb_wrap


def pyrop_ref2str(rop_ref):
    '''Converts a string referenced by ctypes to str
    '''
    if not isinstance(rop_ref, tuple) and not isinstance(rop_ref, list):
        return cast(rop_ref, c_char_p).value
    strings = []
    for ref in rop_ref:
        strings.append(cast(ref, c_char_p).value)
    return strings


ROPD = RopLibDef()


if __name__ == '__main__':
    '''A trivial test
    '''
    rop = RopLib()
    print('The ROP library has been successfully loaded:\n\t' + rop.rnp_version_string_full())
