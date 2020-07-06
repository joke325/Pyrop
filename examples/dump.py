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

# Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/dump.c

import sys
import getopt
import os.path
from pyrop.bind import RopBind
from pyrop.error import RopError

def print_usage(program_name):
    sys.stderr.write(
        "Program dumps PGP packets. \n\nUsage:\n"
        "\t%s [-d|-h] [input.pgp]\n"
        "\t  -d : indicates whether to print packet content. Data is represented as hex\n"
        "\t  -m : dump mpi values\n"
        "\t  -g : dump key fingerprints and grips\n"
        "\t  -j : JSON output\n"
        "\t  -h : prints help and exists\n" %
        os.path.basename(program_name))

def stdin_reader(app_ctx, len_):
    return sys.stdin.read(len_)

def stdout_writer(app_ctx, buf):
    try:
        sys.stdout.write(buf.decode())
        return True
    except IOError: pass
    return False

def execute(argv, json_out=None):
    input_file = None
    raw = False
    mpi = False
    grip = False
    json = False
    help_ = (len(argv) < 2)

    ''' Parse command line options:
        -i input_file [mandatory]: specifies name of the file with PGP packets
        -d : indicates wether to dump whole packet content
        -m : dump mpi contents
        -g : dump key grips and fingerprints
        -j : JSON output
        -h : prints help and exists
    '''
    opts, args = getopt.getopt(argv[1:], 'dmgjh')
    for optt in opts:
        for opt in optt:
            if opt == '-d':
                raw = True
            elif opt == '-m':
                mpi = True
            elif opt == '-g':
                grip = True
            elif opt == '-j':
                json = True
            elif len(opt) > 0:
                help_ = True
    if not help_:
        if len(args) > 0:
            input_file = args[0]

        rop = RopBind()
        try:
            try:
                if input_file is not None:
                    input_ = rop.create_input(path=input_file)
                else:
                    input_ = rop.create_input(reader=stdin_reader)
            except RopError, err:
                print("Failed to open source: error {}".format(hex(err.err_code)))
                raise

            if not json:
                try:
                    output = rop.create_output(writer=stdout_writer)
                except RopError, err:
                    print("Failed to open stdout: error {}".format(hex(err.err_code)))
                    raise
                input_.dump_packets_to_output(output, mpi=mpi, raw=raw, grip=grip)
            else:
                jsn = input_.dump_packets_to_json(mpi=mpi, raw=raw, grip=grip)
                if json_out is None:
                    print(jsn)
                    print('')
                else:
                    json_out.append(jsn)
        except RopError, err:
            # Inform in case of error occured during parsing
            print("Operation failed [error code: {}]".format(hex(err.err_code)))
            raise
        finally:
            rop.close()

    else:
        print_usage(argv[0])


if __name__ == '__main__':
    execute(sys.argv)
