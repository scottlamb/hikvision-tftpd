#!/usr/bin/env python
"""
The Hikvision TFTP handshake (for both cameras and NVRs) is stupid but easy
enough. The client uses the address 192.0.0.64 and expects a TFTP server
running on address 192.0.0.128. It sends a particular packet to the server's
port 9978 from the client port 9979 and expects the server to echo it back.
Once that happens, it proceeds to send a tftp request (on the standard tftp
port, 69) for the file "digicap.dav", which it then installs.

See discussion thread:
https://www.ipcamtalk.com/showthread.php/3647-Hikvision-DS-2032-I-Console-Recovery

This program handles the echo reply. Run alongside a standard TFTP server.
"""

__author__ = 'Scott Lamb'
__license__ = 'MIT'
__email__ = 'slamb@slamb.org'

import errno
import socket
import struct
import sys
import time

_MAGIC_BYTES = struct.pack('20s', 'SWKH')
_MAGIC_CLIENT_ADDR = ('192.0.0.64', 9979)
_MAGIC_SERVER_ADDR = ('192.0.0.128', 9978)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.bind(_MAGIC_SERVER_ADDR)
except socket.error, e:
    if e.errno == errno.EADDRNOTAVAIL:
        print 'Can\'t bind to %s:%d.' % _MAGIC_SERVER_ADDR
        print 'Have you set up the IP?'
        print 'Try running: $ sudo ifconfig eth0:0 %s' % _MAGIC_SERVER_ADDR[0]
        sys.exit(1)
    raise
while True:
    data, addr = sock.recvfrom(len(_MAGIC_BYTES))
    now = time.strftime('%F %T')
    if data == _MAGIC_BYTES and addr == _MAGIC_CLIENT_ADDR:
        sock.sendto(data, addr)
        print '%s: Replied to magic handshake request.' % now
    else:
        print '%s: received unexpected bytes %r from %s:%d' % (
            now, data.encode('hex'), addr[0], addr[1])