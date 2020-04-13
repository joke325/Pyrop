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

import unittest
from os import path, unlink
import json
import sys

TEST_PATH = path.dirname(path.abspath(__file__))
sys.path.append(path.join(path.dirname(TEST_PATH), 'examples'))
import generate
import encrypt
import decrypt
import sign
import verify
import dump

def right_cmp_json(json_, ref_json):
    if isinstance(ref_json, list):
        for idx, item in enumerate(ref_json): right_cmp_json(json_[idx], item)
    elif isinstance(ref_json, dict):
        for key in ref_json: right_cmp_json(json_[key], ref_json[key])
    elif json_ != ref_json: msg = 'FAILED! ({} != {})'.format(json_, ref_json); raise Exception(msg)

class RopExamplesTest(unittest.TestCase):
    def setUp(self):
        for fname in ['pubring.pgp', 'secring.pgp']:
            try: unlink(fname)
            except OSError: pass
        self.test_key_ids = []

    def test_examples(self):
        #Execute
        generate.execute()
        encrypt.execute()
        decrypt.execute()
        if encrypt.message != decrypt.message:
            raise Exception('Decryption Failed!')
        sign.execute()
        for idx in range(2): self.test_key_ids.append(sign.key_ids[idx])
        verify.execute()
        out = []; dump.execute(['dump.py', '-j', 'signed.asc'], out)

        #Parse the dump
        jsn = json.loads(out[0])
        ref_jsn = None
        with open(path.join(TEST_PATH, 'et_json.txt'), 'r') as jf_:
            ref_jsn = jf_.read().replace('b2617b172b2ceae2a1ed72435fc1286cf91da4d0', \
                sign.key_fprints[0].lower())
            ref_jsn = ref_jsn.replace('5fc1286cf91da4d0', sign.key_ids[0].lower())
            ref_jsn = ref_jsn.replace('f1768c67ec5a9ead3061c2befeee14c57b1a12d9', \
                sign.key_fprints[1].lower())
            ref_jsn = ref_jsn.replace('feee14c57b1a12d9', sign.key_ids[1].lower())
            ref_jsn = json.loads(ref_jsn)
        right_cmp_json(jsn, ref_jsn)

    def tearDown(self):
        fnames = ['pubring.pgp', 'secring.pgp', 'encrypted.asc', 'signed.asc']
        for keyid in self.test_key_ids:
            fnames.append('key-%s-pub.asc' % keyid)
            fnames.append('key-%s-sec.asc' % keyid)
        for fname in fnames:
            try: unlink(fname)
            except OSError: pass


if __name__ == '__main__':
    unittest.main()
