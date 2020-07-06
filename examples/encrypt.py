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

# Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/encrypt.c

from datetime import datetime
from pyrop.bind import RopBind
from pyrop.error import RopError

message = "ROP encryption sample message"


def encrypt(rop):
    alt = rop.tagging()
    try:
        # initialize
        ses = rop.create_session(rop.KEYSTORE_GPG, rop.KEYSTORE_GPG)

        keyfile = None
        try:
            # load public keyring - we do not need secret for encryption
            keyfile = rop.create_input(path="pubring.pgp")
            # we may use secret=True and public=True as well
            ses.load_keys(rop.KEYSTORE_GPG, keyfile, public=True)
        except RopError:
            print("Failed to read pubring")
            raise
        finally:
            rop.drop(object_=keyfile)

        try:
            # create memory input and file output objects for the message and encrypted message
            input_ = rop.create_input(message, do_copy=False)
            output = rop.create_output(to_path="encrypted.asc")
            # create encryption operation
            encrpt = ses.op_encrypt_create(input_, output)

            # setup encryption parameters
            encrpt.set_armor(True)
            encrpt.set_file_name("message.txt")
            encrpt.set_file_mtime(datetime.now())
            encrpt.set_compression("ZIP", 6)
            encrpt.set_cipher(rop.ALG_SYMM_AES_256)
            encrpt.set_aead("None")

            # locate recipient's key and add it to the operation context. While we search by userid
            # (which is easier), you can search by keyid, fingerprint or grip.
            key = ses.locate_key("userid", "rsa@key")
            encrpt.add_recipient(key)
            # add encryption password as well
            encrpt.add_password("encpassword", rop.ALG_HASH_SHA256, 0, rop.ALG_SYMM_AES_256)

            # execute encryption operation
            encrpt.execute()

            print("Encryption succeded. Encrypted message written to file encrypted.asc")
        except RopError:
            print("Encryption failed")
            raise

    finally:
        rop.drop(from_=alt)

def execute():
    rop = RopBind()
    try:
        encrypt(rop)
    finally:
        rop.close()


if __name__ == '__main__':
    execute()
