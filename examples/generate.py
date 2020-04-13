#!/usr/bin/env python

# Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/generate.c

from pyrop.bind import RopBind
from pyrop.error import RopError


# RSA key JSON description. 31536000 = 1 year expiration, 15768000 = half year
RSA_KEY_DESC = "{\
    'primary': {\
        'type': 'RSA',\
        'length': 2048,\
        'userid': 'rsa@key',\
        'expiration': 31536000,\
        'usage': ['sign'],\
        'protection': {\
            'cipher': 'AES256',\
            'hash': 'SHA256'\
        }\
    },\
    'sub': {\
        'type': 'RSA',\
        'length': 2048,\
        'expiration': 15768000,\
        'usage': ['encrypt'],\
        'protection': {\
            'cipher': 'AES256',\
            'hash': 'SHA256'\
        }\
    }\
}"

CURVE_25519_KEY_DESC = "{\
    'primary': {\
        'type': 'EDDSA',\
        'userid': '25519@key',\
        'expiration': 0,\
        'usage': ['sign'],\
        'protection': {\
            'cipher': 'AES256',\
            'hash': 'SHA256'\
        }\
    },\
    'sub': {\
        'type': 'ECDH',\
        'curve': 'Curve25519',\
        'expiration': 15768000,\
        'usage': ['encrypt'],\
        'protection': {\
            'cipher': 'AES256',\
            'hash': 'SHA256'\
        }\
    }\
}"


# basic pass provider implementation, which always return 'password' for key protection.
# You may ask for password via stdin, or choose password based on key properties, whatever else
def example_pass_provider(session, app_ctx, key, pgp_context, buf_len):
    if pgp_context == 'protect':
        return True, 'password'
    return False, None

# this simple helper function just prints armored key, searched by userid, to stdout
def print_key(rop, ses, uid, secret):
    # you may search for the key via userid, keyid, fingerprint, grip
    key = ses.locate_key("userid", uid)
    # create in-memory output structure to later use buffer
    keydata = rop.create_output(max_alloc=0)
    try:
        key.export(keydata, public=not secret, secret=secret, subkey=True, armored=True)
        # get key's contents from the output structure
        buf = keydata.memory_get_buf(False)
        print(buf)
    finally:
        rop.drop(object_=keydata)

def export_key(rop, ses, uid, secret):
    # you may search for the key via userid, keyid, fingerprint, grip
    key = ses.locate_key("userid", uid)
    # get key's id and build filename
    filename = "key-{}-{}.asc".format(key.keyid, "sec" if secret else "pub")
    keyfile = rop.create_output(to_path=filename)
    try:
        key.export(keyfile, public=not secret, secret=secret, subkey=True, armored=True)
    finally:
        rop.drop(object_=keyfile)

# this example function generates RSA/RSA and Eddsa/X25519 keypairs
def generate_keys(rop):
    alt = rop.tagging()
    try:
        # initialize
        ses = rop.create_session(rop.KEYSTORE_GPG, rop.KEYSTORE_GPG)

        try:
            # set password provider
            ses.set_pass_provider(example_pass_provider, None)
            # generate EDDSA/X25519 keypair
            key_grips = ses.generate_key_json(CURVE_25519_KEY_DESC)
            # generate RSA keypair
            key_grips = ses.generate_key_json(RSA_KEY_DESC)
            print("Generated RSA key/subkey:\n%s\n" % key_grips)
        except RopError:
            print("Failed to generate keys")
            raise

        keyfile = None
        try:
            # create file output object and save public keyring with generated keys, overwriting
            # previous file if any. You may use max_alloc here as well.
            keyfile = rop.create_output(to_path="pubring.pgp")
            ses.save_keys(rop.KEYSTORE_GPG, keyfile, public=True)
        except RopError:
            print("Failed to save pubring")
            raise
        finally:
            rop.drop(object_=keyfile)

        keyfile = None
        try:
            # create file output object and save secret keyring with generated keys
            keyfile = rop.create_output(to_path="secring.pgp")
            ses.save_keys(rop.KEYSTORE_GPG, keyfile, secret=True)
        except RopError:
            print("Failed to save secring")
            raise
        finally:
            rop.drop(object_=keyfile)

    finally:
        rop.drop(from_=alt)

def output_keys(rop):
    alt = rop.tagging()
    try:
        # initialize
        ses = rop.create_session(rop.KEYSTORE_GPG, rop.KEYSTORE_GPG)

        keyfile = None
        try:
            # load keyrings
            keyfile = rop.create_input(path="pubring.pgp")
            # actually, we may exclude the public  to not check key types
            ses.load_keys(rop.KEYSTORE_GPG, keyfile, public=True)
        except RopError:
            print("Failed to read pubring")
            raise
        finally:
            rop.drop(object_=keyfile)

        keyfile = None
        try:
            keyfile = rop.create_input(path="secring.pgp")
            ses.load_keys(rop.KEYSTORE_GPG, keyfile, secret=True)
        except RopError:
            print("Failed to read secring")
            raise
        finally:
            rop.drop(object_=keyfile)

        try:
            # print armored keys to the stdout
            print_key(rop, ses, "rsa@key", False)
            print_key(rop, ses, "rsa@key", True)
            print_key(rop, ses, "25519@key", False)
            print_key(rop, ses, "25519@key", True)
        except:
            print("Failed to print armored key(s)")
            raise

        try:
            # write armored keys to the files, named key-<keyid>-pub.asc/named key-<keyid>-sec.asc
            export_key(rop, ses, "rsa@key", False)
            export_key(rop, ses, "rsa@key", True)
            export_key(rop, ses, "25519@key", False)
            export_key(rop, ses, "25519@key", True)
        except:
            print("Failed to write armored key(s) to file")
            raise

    finally:
        rop.drop(from_=alt)

def execute():
    rop = RopBind()
    try:
        generate_keys(rop)
        output_keys(rop)
    finally:
        rop.clear()


if __name__ == '__main__':
    execute()
