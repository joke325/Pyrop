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

# Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/verify.c

from pyrop.bind import RopBind
from pyrop.error import RopError


def example_key_provider(session, app_ctx, identifier_type, identifier, secret):
    if identifier_type == "keyid":
        filename = "key-%s-%s.asc" % (identifier, "sec" if secret else "pub")
        try:
            rop = session.bind
            err_desc = "failed to open key file %s" % filename
            input_ = rop.create_input(path=filename)

            err_desc = "failed to load key from file %s" % filename
            session.load_keys(rop.KEYSTORE_GPG, input_, public=True, secret=True)
        except RopError:
            print(err_desc)


def verify_(rop):
    alt = rop.tagging()
    try:
        # initialize
        ses = rop.create_session(rop.KEYSTORE_GPG, rop.KEYSTORE_GPG)

        # we do not load any keys here since we'll use key provider
        ses.set_key_provider(example_key_provider, None)

        try:
            # create file input and memory output objects for the signed message
            # and verified message
            err_desc = "Failed to open file 'signed.asc'. Did you run the sign example?"
            input_ = rop.create_input(path="signed.asc")

            err_desc = "Failed to create output object"
            output = rop.create_output(max_alloc=0)

            err_desc = "Failed to create verification context"
            verify = ses.op_verify_create(input_, output)

            err_desc = "Failed to execute verification operation"
            verify.execute()

            # now check signatures and get some info about them
            err_desc = "Failed to get signature count"
            sigcount = verify.signature_count

            for idx in range(sigcount):
                rop.tagging()

                err_desc = "Failed to get signature %d" % idx
                sig = verify.get_signature_at(idx)

                err_desc = "failed to get signature's %d key" % idx
                key = sig.get_key()

                err_desc = "failed to get key id %d" % idx

                print("Status for signature from key {} : {}".format(key.keyid, sig.status))
                rop.drop()

        except RopError:
            print(err_desc)
            raise

        # get the verified message from the output structure
        buf = output.memory_get_str(False)
        print("Verified message: {}".format(buf))

    finally:
        rop.drop(from_=alt)

def execute():
    rop = RopBind()
    try:
        verify_(rop)
    finally:
        rop.close()


if __name__ == '__main__':
    execute()
