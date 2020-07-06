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

# Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/sign.c

from datetime import datetime, timedelta
from pyrop.bind import RopBind
from pyrop.error import RopError

key_ids = ['Dummy', 'Dummy']
key_fprints = ['Dummy', 'Dummy']


# sample pass provider implementation, which always return 'password'
def example_pass_provider(session, app_ctx, key, pgp_context, buf_len):
    return True, "password"


def sign_(rop):
    message = "ROP signing sample message"

    alt = rop.tagging()
    try:
        # initialize
        ses = rop.create_session(rop.KEYSTORE_GPG, rop.KEYSTORE_GPG)

        keyfile = None
        try:
            # load secret keyring, as it is required for signing. However, you may need
            # to load public keyring as well to validate key's signatures.
            err_desc = "Failed to open secring.pgp. Did you run ./generate.py sample?"
            keyfile = rop.create_input(path="secring.pgp")

            # we may use public=True and secret=True as well
            err_desc = "Failed to read secring.pgp"
            ses.load_keys(rop.KEYSTORE_GPG, keyfile, secret=True)
        except RopError:
            print(err_desc)
            raise
        finally:
            rop.drop(object_=keyfile)

        # set the password provider - we'll need password to unlock secret keys
        ses.set_pass_provider(example_pass_provider, None)

        # create file input and memory output objects for the encrypted message
        # and decrypted message
        try:
            err_desc = "Failed to create input object"
            input_ = rop.create_input(message, do_copy=False)

            err_desc = "Failed to create output object"
            output = rop.create_output(to_path="signed.asc")

            # initialize and configure sign operation, use op_sign_create(cleartext/detached)
            # for cleartext or detached signature
            err_desc = "Failed to create sign operation"
            sign = ses.op_sign_create(input_, output)
        except RopError:
            print(err_desc)
            raise

        # armor, file name, compression
        sign.set_armor(True)
        sign.set_file_name("message.txt")
        sign.set_file_mtime(datetime.now())
        sign.set_compression("ZIP", 6)
        # signatures creation time - by default will be set to the current time as well
        sign.set_creation_time(datetime.now())
        # signatures expiration time - by default will be 0, i.e. never expire
        sign.set_expiration(timedelta(days=365))
        # set hash algorithm - should be compatible for all signatures
        sign.set_hash(rop.ALG_HASH_SHA256)

        try:
            # now add signatures. First locate the signing key, then add and setup signature
            # RSA signature
            err_desc = "Failed to locate signing key rsa@key."
            key = ses.locate_key("userid", "rsa@key")
            global key_ids
            global key_fprints
            key_ids[0] = key.keyid
            key_fprints[0] = key.fprint

            err_desc = "Failed to add signature for key rsa@key."
            sign.add_signature(key)

            # EdDSA signature
            err_desc = "Failed to locate signing key 25519@key."
            key = ses.locate_key("userid", "25519@key")
            key_ids[1] = key.keyid
            key_fprints[1] = key.fprint

            err_desc = "Failed to add signature for key 25519@key."
            sign.add_signature(key)

            # finally do signing
            err_desc = "Failed to add signature for key 25519@key."
            sign.execute()

            print("Signing succeeded. See file signed.asc.")
        except RopError:
            print(err_desc)
            raise

    finally:
        rop.drop(from_=alt)

def execute():
    rop = RopBind()
    try:
        sign_(rop)
    finally:
        rop.close()


if __name__ == '__main__':
    execute()
