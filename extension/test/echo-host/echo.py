#!/usr/bin/python3 -I
"""Native messaging echo host for the driver's tests (story E7-S7b).

Reads each message (a 4-byte length in native byte order, then UTF-8 JSON)
and answers {"echo": message, "caller": the origin Chrome passed}. Exits
when standard input closes.
"""
import json
import struct
import sys

stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
while True:
    head = stdin.read(4)
    if len(head) < 4:
        break
    message = json.loads(stdin.read(struct.unpack("=I", head)[0]))
    answer = json.dumps({"echo": message, "caller": sys.argv[1:2]}).encode()
    stdout.write(struct.pack("=I", len(answer)) + answer)
    stdout.flush()
