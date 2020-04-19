#!/usr/bin/env python

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
        rop.clear()


if __name__ == '__main__':
    execute()
