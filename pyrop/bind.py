#!/usr/bin/env python

'''A Binding wrapper
'''
__version__ = "0.1.1"

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

from .rop.lib import RopLib, PyRopUtils, ROPD
from .rop.err import ROPE
from .util import _call_rop_func, _get_rop_string, _new_rop_obj, _get_str_prop
from .error import RopError
from .session import RopSession
from .io import RopInput, RopOutput


class RopBind(object):
    '''Root object of bindind for the RNP OpenPGP library
    '''

    def __init__(self, check_lib_ver=True):
        self.__cnt = 1
        self.__lib = RopLib()
        self.__tags = [self.__cnt]
        self.__t2objs = dict() #tag->set
        if check_lib_ver and not (self.__lib.rnp_version() >= self.__lib.rnp_version_for(0, 9, 0)):
            raise RopError(self.ROP_ERROR_LIBVERSION)

    @property
    def _lib(self):
        return self.__lib

    # API

    @property
    def default_homedir(self):
        return _get_str_prop(self.__lib, self.__lib.rnp_get_default_homedir)
    @property
    def version_string(self):
        return self.__lib.rnp_version_string()
    @property
    def version_string_full(self):
        return self.__lib.rnp_version_string_full()
    @property
    def version(self):
        return self.__lib.rnp_version()
    @property
    def version_commit_timestamp(self):
        return self.__lib.rnp_version_commit_timestamp()

    def get_homedir_info(self, homedir):
        info = _call_rop_func(self.__lib.rnp_detect_homedir_info, 4, homedir)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, info)

    def version_for(self, major, minor, patch):
        return self.__lib.rnp_version_for(major, minor, patch)

    def version_major(self, version):
        return self.__lib.rnp_version_major(version)

    def version_minor(self, version):
        return self.__lib.rnp_version_minor(version)

    def version_patch(self, version):
        return self.__lib.rnp_version_patch(version)

    def result_to_string(self, result):
        return self.__lib.rnp_result_to_string(result)

    def enable_debug(self, file_):
        return self.__lib.rnp_enable_debug(file_)

    def disable_debug(self):
        return self.__lib.rnp_disable_debug()

    def supports_feature(self, type_, name):
        return _call_rop_func(self.__lib.rnp_supports_feature, 1, type_, name)

    def supported_features(self, type_):
        result = _call_rop_func(self.__lib.rnp_supported_features, 1, type_)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, result)

    def detect_key_format(self, buf, buf_len):
        format_ = _call_rop_func(self.__lib.rnp_detect_key_format, 1, buf, buf_len)
        return _get_rop_string(self.__lib, ROPE.RNP_SUCCESS, format_, False)

    def calculate_iterations(self, hash_, msec):
        return _call_rop_func(self.__lib.rnp_calculate_iterations, 1, hash_, msec)


    def create_session(self, pub_format, sec_format, tag=0):
        '''F(pub_format: str, sec_format: str, tag: int) -> RopSession
        '''
        outs = []
        ret = self.__lib.rnp_ffi_create(outs, pub_format, sec_format)
        return _new_rop_obj(self, ret, outs[-1], RopSession, tag)

    def create_input(self, buf=None, buf_len=0, do_copy=False, path=None, tag=0, **others):
        '''F(buf: bytes, buf_len: int, do_copy: bool, tag: int) -> RopInput
        F(path: str, tag: int) -> RopInput
        F(reader: G(ctx: obj, len: int), closer: H(ctx: obj), app_ctx: obj, tag: int) -> RopInput
        '''
        input_ = None
        ret = self.ROP_ERROR_BAD_PARAMETERS
        outs = [None]
        reader = None
        closer = None

        if path is not None:
            ret = self.__lib.rnp_input_from_path(outs, path)
        elif buf is not None:
            ret = self.__lib.rnp_input_from_memory(outs, buf, \
                buf_len if buf_len > 0 else len(buf), do_copy)
        else:
            reader = others.get('reader')
            if reader is not None:
                closer = others.get('closer')
                app_ctx = others.get('app_ctx')
                reader = RopLib.Rop_input_reader_t(PyRopUtils.reshape_reader_cb(reader))
                closer = RopLib.Rop_input_closer_t(PyRopUtils.reshape_rcloser_cb(closer)) \
                    if closer is not None else RopLib.Rop_input_closer_t()
                ret = self.__lib.rnp_input_from_callback(outs, reader, closer, app_ctx)

        input_ = _new_rop_obj(self, ret, outs[-1], RopInput, tag)
        if reader is not None:
            input_._reader = reader
        if closer is not None:
            input_._rcloser = closer
        return input_

    def create_output(self, to_file=None, to_path=None, max_alloc=None, tag=0, **others):
        '''F(to_file: str, overwrite: bool, random: bool, tag: int) -> RopOutput
        F(to_path: str, tag: int) -> RopOutput
        F(max_alloc: int, tag: int) -> RopOutput
        F(writer: G(ctx: obj, data: bytes), closer: H(ctx: obj, discard: bool), app_ctx: obj,
            tag: int) -> RopOutput
        F(tag: int) -> RopOutput
        '''
        output = None
        ret = self.ROP_ERROR_BAD_PARAMETERS
        outs = [None]
        writer = None
        closer = None

        if to_path is not None:
            ret = self.__lib.rnp_output_to_path(outs, to_path)
        elif to_file is not None:
            overwrite = others.get('overwrite')
            flags = (ROPD.RNP_OUTPUT_FILE_OVERWRITE if overwrite else 0)
            random = others.get('random')
            flags |= (ROPD.RNP_OUTPUT_FILE_RANDOM if random else 0)
            ret = self.__lib.rnp_output_to_file(outs, to_file, flags)
        elif max_alloc is not None:
            ret = self.__lib.rnp_output_to_memory(outs, max_alloc)
        else:
            writer = others.get('writer')
            if writer is not None:
                closer = others.get('closer')
                app_ctx = others.get('app_ctx')
                writer = RopLib.Rop_output_writer_t(PyRopUtils.reshape_writer_cb(writer))
                closer = RopLib.Rop_output_closer_t(PyRopUtils.reshape_wcloser_cb(closer)) \
                    if closer is not None else RopLib.Rop_output_closer_t()
                ret = self.__lib.rnp_output_to_callback(outs, writer, closer, app_ctx)
            else:
                ret = self.__lib.rnp_output_to_null(outs)
        output = _new_rop_obj(self, ret, outs[-1], RopOutput, tag)
        if writer is not None:
            output._writer = writer
        if closer is not None:
            output._wcloser = closer
        return output

    def tagging(self, tag=0):
        '''F(tag: int) -> int
        Returns a tag of subsequestly allocated objects
        '''
        self.__cnt += 1
        self.__tags.append(tag if tag != 0 else self.__cnt)
        return self.__tags[-1]

    def drop(self, tag=0, object_=None, objects=None, from_=None):
        '''F(tag: int) -> None
        F(from_: int) -> None
        F(object_: obj) -> None
        F(objects: (obj)) -> None
        Release object(s)
        '''
        ret = ROPE.RNP_SUCCESS

        # collect tags to delete
        dtags = [tag]
        if from_ is not None:
            try:
                dtags = self.__tags[self.__tags.index(from_):]
            except ValueError:
                del dtags[:]
        elif tag == 0 and len(self.__tags) > 1:
            dtags = self.__tags[-1:]

        # collect objects to delete
        objset = (set(objects) if objects is not None else None)
        if object_ is not None:
            objset = (objset if objset is not None else set())
            objset.add(object_)

        # delete the dtags and objset conjuction
        for tg_ in reversed(dtags if tag >= 0 else self.__tags):
            objs = self.__t2objs.get(tg_)
            if objs is not None:
                dellist = (list(objset.intersection(objs.keys())) \
                    if objset is not None else objs.keys())
                for obj in sorted(dellist, key=lambda x: objs[x], reverse=True):
                    err = obj._close()
                    ret = (err if ret == ROPE.RNP_SUCCESS else ret)
                    del objs[obj]
                if len(objs) == 0:
                    del self.__t2objs[tg_]
            # delete obsolete tags
            if not self.__t2objs.has_key(tg_):
                try:
                    self.__tags.remove(tg_)
                except ValueError: pass

        if ret != ROPE.RNP_SUCCESS:
            raise RopError(ret)

    def clear(self):
        self.drop(-1)

    # Tools

    def _put_obj(self, obj, tag):
        otag = tag if tag != 0 else self.__tags[-1]
        objs = self.__t2objs.get(otag)
        if objs is None:
            self.__t2objs[otag] = objs = {}
        self.__cnt += 1
        objs[obj] = self.__cnt

    def __str__(self):
        return "tags = " + str(self.__tags) + "\nt2objs = " + str(self.__t2objs)

    # Constants

    @property
    def KEYSTORE_GPG(self): return ROPD.RNP_KEYSTORE_GPG
    @property
    def KEYSTORE_KBX(self): return ROPD.RNP_KEYSTORE_KBX
    @property
    def KEYSTORE_G10(self): return ROPD.RNP_KEYSTORE_G10
    @property
    def KEYSTORE_GPG21(self): return ROPD.RNP_KEYSTORE_GPG21

    @property
    def ALG_HASH_MD5(self): return ROPD.RNP_ALGNAME_MD5
    @property
    def ALG_HASH_SHA1(self): return ROPD.RNP_ALGNAME_SHA1
    @property
    def ALG_HASH_SHA256(self): return ROPD.RNP_ALGNAME_SHA256
    @property
    def ALG_HASH_SHA384(self): return ROPD.RNP_ALGNAME_SHA384
    @property
    def ALG_HASH_SHA512(self): return ROPD.RNP_ALGNAME_SHA512
    @property
    def ALG_HASH_SHA224(self): return ROPD.RNP_ALGNAME_SHA224
    @property
    def ALG_HASH_SHA3_256(self): return ROPD.RNP_ALGNAME_SHA3_256
    @property
    def ALG_HASH_SHA3_512(self): return ROPD.RNP_ALGNAME_SHA3_512
    @property
    def ALG_HASH_RIPEMD160(self): return ROPD.RNP_ALGNAME_RIPEMD160
    @property
    def ALG_HASH_SM3(self): return ROPD.RNP_ALGNAME_SM3
    @property
    def ALG_HASH_DEFAULT(self): return ALG_HASH_SHA256
    @property
    def ALG_SYMM_IDEA(self): return ROPD.RNP_ALGNAME_IDEA
    @property
    def ALG_SYMM_TRIPLEDES(self): return ROPD.RNP_ALGNAME_TRIPLEDES
    @property
    def ALG_SYMM_CAST5(self): return ROPD.RNP_ALGNAME_CAST5
    @property
    def ALG_SYMM_BLOWFISH(self): return ROPD.RNP_ALGNAME_BLOWFISH
    @property
    def ALG_SYMM_TWOFISH(self): return ROPD.RNP_ALGNAME_TWOFISH
    @property
    def ALG_SYMM_AES_128(self): return ROPD.RNP_ALGNAME_AES_128
    @property
    def ALG_SYMM_AES_192(self): return ROPD.RNP_ALGNAME_AES_192
    @property
    def ALG_SYMM_AES_256(self): return ROPD.RNP_ALGNAME_AES_256
    @property
    def ALG_SYMM_CAMELLIA_128(self): return ROPD.RNP_ALGNAME_CAMELLIA_128
    @property
    def ALG_SYMM_CAMELLIA_192(self): return ROPD.RNP_ALGNAME_CAMELLIA_192
    @property
    def ALG_SYMM_CAMELLIA_256(self): return ROPD.RNP_ALGNAME_CAMELLIA_256
    @property
    def ALG_SYMM_SM4(self): return ROPD.RNP_ALGNAME_SM4
    @property
    def ALG_SYMM_DEFAULT(self): return ROPD.ALG_SYMM_AES_256
    @property
    def ALG_ASYM_RSA(self): return ROPD.RNP_ALGNAME_RSA
    @property
    def ALG_ASYM_ELGAMAL(self): return ROPD.RNP_ALGNAME_ELGAMAL
    @property
    def ALG_ASYM_DSA(self): return ROPD.RNP_ALGNAME_DSA
    @property
    def ALG_ASYM_ECDH(self): return ROPD.RNP_ALGNAME_ECDH
    @property
    def ALG_ASYM_ECDSA(self): return ROPD.RNP_ALGNAME_ECDSA
    @property
    def ALG_ASYM_EDDSA(self): return ROPD.RNP_ALGNAME_EDDSA
    @property
    def ALG_ASYM_SM2(self): return ROPD.RNP_ALGNAME_SM2
    @property
    def ALG_PLAINTEXT(self): return ROPD.RNP_ALGNAME_PLAINTEXT
    @property
    def ALG_CRC24(self): return ROPD.RNP_ALGNAME_CRC24

    @property
    def ROP_ERROR_BAD_PARAMETERS(self): return 0x80000000
    @property
    def ROP_ERROR_LIBVERSION(self): return 0x80000001
    @property
    def ROP_ERROR_INTERNAL(self): return 0x80000002


if __name__ == '__main__':
    #A trivial test
    try:
        raise RopError(0)
    except RopError:
        print('Starting:')
    rop = RopBind()
    try:
        print('homedir = ' + rop.default_homedir)
        ses = rop.create_session("GPG", "GPG")
        print('OK ' + str(ses))
    except RopError, ex:
        print(ex.message)
    finally:
        rop.clear()
