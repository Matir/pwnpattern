"""
Copyright 2016 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Description:
Generate patterns for finding offsets, typically used in exploiting memory
corruption vulnerabilities.  This is intended to replicate the patterns produced
by metasploit's pattern_create.rb and pattern_offset.rb.
"""

import struct
import sys

_default_sets = [
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
]

_default_length = 1024
_stderr = sys.stderr.write

def pattern_create(length=_default_length, sets=None):
    """Generate a pattern."""
    sets = sets or _default_sets
    assert len(sets) in (2,3)
    
    output = []

    while len(output) < length:
        l = len(output)
        charset = sets[l % len(sets)]
        set_interval = len(sets)
        for s in sets[(l % len(sets)) + 1:]:
            set_interval *= len(s)
        output.append(charset[(l / set_interval) % len(charset)])

    return ''.join(output)


def interpret_target(target):
    fmts = {4: 'H', 8: 'L', 16: 'Q'}
    if target.startswith('0x'):
        # This is almost certainly hex
        try:
            val = int(target, 16)
            fmt = '<' + fmts.get(len(target) - 2, 'L')
            return struct.pack(fmt, val)
        except ValueError:
            pass
    if len(target) in (8, 16):
        # These lengths are commonly hex
        try:
            val = int(target, 16)
            fmt = '<' + fmts.get(len(target), 'L')
            return struct.pack(fmt, val)
        except ValueError:
            pass
    return target


def pattern_offset(target, length=_default_length, sets=None):
    """Find the offset for the pattern."""
    pattern = pattern_create(length, sets)
    target = interpret_target(target)
    try:
        return pattern.index(target)
    except ValueError:
        pass


def main(argv):
    """Interactive use."""
    binary = argv[0]
    args = argv[1:]
    if "create" in binary:
        mode = "create"
    elif "offset" in binary:
        mode = "offset"
    else:
        try:
            mode = argv[1]
            args = args[1:]
        except:
            return usage()
    if mode == "create":
        length = int(args[0]) if args else _default_length
        sets = args[1:] if len(args) > 2 else None
        sys.stdout.write(pattern_create(length, sets))
        return
    if mode == "offset":
        target = args[0]
        length = int(args[1]) if len(args) > 1 else _default_length
        sets = args[2:] if len(args) > 3 else None
        sys.stdout.write('[*] Match at offset {}\n'.format(
            pattern_offset(target, length, sets)))
        return
    usage()


def usage():
    _stderr("{} <mode> [length] [set_a] [set_b] [set_c]\n".format(sys.argv[0]))    


if __name__ == "__main__":
    main(sys.argv)
