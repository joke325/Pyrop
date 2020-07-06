#!/usr/bin/env python

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

# Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/decrypt.c

from pyrop.bind import RopBind
from pyrop.error import RopError

message = "Dummy"


def example_pass_provider(session, app_ctx, key, pgp_context, buf_len):
    if pgp_context == 'decrypt (symmetric)':
        return True, 'encpassword'
    if pgp_context == 'decrypt':
        return True, 'password'
    return False, None


def decrypt(rop, usekeys):
    alt = rop.tagging()
    try:
        # initialize FFI object
        ses = rop.create_session(rop.KEYSTORE_GPG, rop.KEYSTORE_GPG)

        # check whether we want to use key or password for decryption
        if usekeys:
            try:
                # load secret keyring, as it is required for public-key decryption. However, you may
                # need to load public keyring as well to validate key's signatures.
                keyfile = rop.create_input(path="secring.pgp")
                # we may use secret=True and public=True as well
                ses.load_keys(rop.KEYSTORE_GPG, keyfile, secret=True)
            except RopError:
                print("Failed to read secring")
                raise
            finally:
                rop.drop(object_=keyfile)

        # set the password provider
        ses.set_pass_provider(example_pass_provider, None)
        try:
            # create file input and memory output objects for the encrypted message and decrypted
            # message
            input_ = rop.create_input(path="encrypted.asc")
            output = rop.create_output(max_alloc=0)
            ses.decrypt(input_, output)
            # get the decrypted message from the output structure
            buf = output.memory_get_str(False)
        except RopError:
            print("Public-key decryption failed")
            raise

        print("Decrypted message ({}):\n{}\n".format("with key" if usekeys else \
            "with password", buf))
        global message
        message = buf

    finally:
        rop.drop(from_=alt)

def execute():
    rop = RopBind()
    try:
        decrypt(rop, True)
        decrypt(rop, False)
    finally:
        rop.close()


if __name__ == '__main__':
    execute()
