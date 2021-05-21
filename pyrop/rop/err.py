'''Wrapped library error codes
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

class RopErr(object):
    '''Error codes definitions
    '''

    def __init__(self):
        self.__rnp_success = 0x00000000
        self.__rnp_error_generic = 0x10000000
        self.__rnp_error_access = 0x11000000
        self.__rnp_error_bad_state = 0x12000000
        self.__rnp_error_not_enough_data = 0x13000000

    # Common error codes
    @property
    def RNP_SUCCESS(self): return self.__rnp_success

    @property
    def RNP_ERROR_GENERIC(self): return self.__rnp_error_generic
    @property
    def RNP_ERROR_BAD_FORMAT(self): return self.__rnp_error_generic+1
    @property
    def RNP_ERROR_BAD_PARAMETERS(self): return self.__rnp_error_generic+2
    @property
    def RNP_ERROR_NOT_IMPLEMENTED(self): return self.__rnp_error_generic+3
    @property
    def RNP_ERROR_NOT_SUPPORTED(self): return self.__rnp_error_generic+4
    @property
    def RNP_ERROR_OUT_OF_MEMORY(self): return self.__rnp_error_generic+5
    @property
    def RNP_ERROR_SHORT_BUFFER(self): return self.__rnp_error_generic+6
    @property
    def RNP_ERROR_NULL_POINTER(self): return self.__rnp_error_generic+7

    # Storage
    @property
    def RNP_ERROR_ACCESS(self): return self.__rnp_error_access
    @property
    def RNP_ERROR_READ(self): return self.__rnp_error_access+1
    @property
    def RNP_ERROR_WRITE(self): return self.__rnp_error_access+2

    # Crypto
    @property
    def RNP_ERROR_BAD_STATE(self): return self.__rnp_error_bad_state
    @property
    def RNP_ERROR_MAC_INVALID(self): return self.__rnp_error_bad_state+1
    @property
    def RNP_ERROR_SIGNATURE_INVALID(self): return self.__rnp_error_bad_state+2
    @property
    def RNP_ERROR_KEY_GENERATION(self): return self.__rnp_error_bad_state+3
    @property
    def RNP_ERROR_BAD_PASSWORD(self): return self.__rnp_error_bad_state+4
    @property
    def RNP_ERROR_KEY_NOT_FOUND(self): return self.__rnp_error_bad_state+5
    @property
    def RNP_ERROR_NO_SUITABLE_KEY(self): return self.__rnp_error_bad_state+6
    @property
    def RNP_ERROR_DECRYPT_FAILED(self): return self.__rnp_error_bad_state+7
    @property
    def RNP_ERROR_RNG(self): return self.__rnp_error_bad_state+8
    @property
    def RNP_ERROR_SIGNING_FAILED(self): return self.__rnp_error_bad_state+9
    @property
    def RNP_ERROR_NO_SIGNATURES_FOUND(self): return self.__rnp_error_bad_state+10

    @property
    def RNP_ERROR_SIGNATURE_EXPIRED(self): return self.__rnp_error_bad_state+11
    @property
    def RNP_ERROR_VERIFICATION_FAILED(self): return self.__rnp_error_bad_state+12

    # Parsing
    @property
    def RNP_ERROR_NOT_ENOUGH_DATA(self): return self.__rnp_error_not_enough_data
    @property
    def RNP_ERROR_UNKNOWN_TAG(self): return self.__rnp_error_not_enough_data+1
    @property
    def RNP_ERROR_PACKET_NOT_CONSUMED(self): return self.__rnp_error_not_enough_data+2
    @property
    def RNP_ERROR_NO_USERID(self): return self.__rnp_error_not_enough_data+3
    @property
    def RNP_ERROR_EOF(self): return self.__rnp_error_not_enough_data+4


ROPE = RopErr()
