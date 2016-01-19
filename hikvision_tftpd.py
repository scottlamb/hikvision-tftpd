#!/usr/bin/env python
"""
Unbrick a Hikvision device. Use as follows:

$ ifconfig eth0:0 192.0.0.128
$ curl -o digicap.dav <url of firmware>
$ sudo ./hikvision_tftpd.py

The Hikvision TFTP handshake (for both cameras and NVRs) is stupid but easy
enough. The client uses the address 192.0.0.64 and expects a TFTP server
running on address 192.0.0.128. It sends a particular packet to the server's
port 9978 from the client port 9979 and expects the server to echo it back.
Once that happens, it proceeds to send a tftp request (on the standard tftp
port, 69) for the file "digicap.dav", which it then installs. The tftp server
must reply from port 69 (unlike the tftpd package that comes with Debian).

This script handles both the handshake and the actual TFTP transfer.
The TFTP server is very simple but appears to be good enough.

See discussion thread:
https://www.ipcamtalk.com/showthread.php/3647-Hikvision-DS-2032-I-Console-Recovery
"""

__author__ = 'Scott Lamb'
__license__ = 'MIT'
__email__ = 'slamb@slamb.org'

import errno
import os
import socket
import struct
import sys
import threading
import time

_HANDSHAKE_BYTES = struct.pack('20s', 'SWKH')
_CLIENT_IP = '192.0.0.64'
_SERVER_IP = '192.0.0.128'
_HANDSHAKE_CLIENT_ADDR = (_CLIENT_IP, 9979)
_HANDSHAKE_SERVER_ADDR = (_SERVER_IP, 9978)
_TFTP_SERVER_ADDR = (_SERVER_IP, 69)

_FILENAME = 'digicap.dav'

# See https://tools.ietf.org/html/rfc1350
_TFTP_OPCODE_RRQ = 1
_TFTP_OPCODE_DATA = 3
_TFTP_OPCODE_ACK = 4
_TFTP_RRQ_PREFIX = struct.pack('>h', _TFTP_OPCODE_RRQ) + _FILENAME + '\x00'
_TFTP_ACK_PREFIX = struct.pack('>h', _TFTP_OPCODE_ACK)
_BLOCK_SIZE = 512

def handshake_loop(sock):
    while True:
        pkt, addr = sock.recvfrom(len(_HANDSHAKE_BYTES))
        now = time.strftime('%F %T')
        if pkt == _HANDSHAKE_BYTES and addr == _HANDSHAKE_CLIENT_ADDR:
            sock.sendto(pkt, addr)
            print '%s: Replied to magic handshake request.' % now
        else:
            print '%s: received unexpected bytes %r from %s:%d' % (
                now, pkt.encode('hex'), addr[0], addr[1])

def tftp_after(sock, file_contents, prev_block, addr):
    block = prev_block + 1
    start_byte = prev_block * _BLOCK_SIZE
    if start_byte > len(file_contents):
        return
    block_data = file_contents[start_byte:start_byte+_BLOCK_SIZE]
    pkt = (struct.pack('>hh', _TFTP_OPCODE_DATA, block) + block_data)
    sock.sendto(pkt, addr)
    now = time.strftime('%F %T')
    print '%s: sending block %d (%d bytes%s)' % (
        now, block, len(block_data),
        ', done' if len(block_data < _BLOCK_SIZE else '')

def tftp_loop(sock, file_contents):
    # TODO: This should retry DATA if an ACK isn't received soon enough.
    # For now, it's entirely reactive.
    while True:
        pkt, addr = sock.recvfrom(len(_HANDSHAKE_BYTES))
        now = time.strftime('%F %T')
        if pkt.startswith(_TFTP_RRQ_PREFIX):
            print '%s: starting transfer' % now
            tftp_after(sock, file_contents, 0, addr)
        elif pkt.startswith(_TFTP_ACK_PREFIX):
            (block,) = struct.unpack('>h', pkt[len(_TFTP_ACK_PREFIX):])
            print '%s: received acknowledgement for block %d' % (now, block)
            tftp_after(sock, file_contents, block, addr)
        else:
            print '%s: received unexpected bytes %r from %s:%d' % (
                now, pkt.encode('hex'), addr[0], addr[1])

handshake_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    handshake_sock.bind(_HANDSHAKE_SERVER_ADDR)
except socket.error, e:
    print 'Error: can\'t bind to %s:%d.' % _HANDSHAKE_SERVER_ADDR
    if e.errno == errno.EADDRNOTAVAIL:
        print 'IP address is not set up.'
        print 'Try running: $ sudo ifconfig eth0:0 %s' % (
            _HANDSHAKE_SERVER_ADDR[0])
        sys.exit(1)
    raise
tftp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    tftp_sock.bind(_TFTP_SERVER_ADDR)
except socket.error, e:
    print 'Error: can\'t bind to %s:%d.' % _TFTP_SERVER_ADDR
    if e.errno == errno.EACCES:
        print 'Please run with CAP_SYS_ADMIN or as root.'
        sys.exit(1)
    if e.errno == errno.EADDRINUSE:
        print 'There seems to be another TFTP server running.'
        sys.exit(1)
    raise
try:
    file_contents = open(_FILENAME, 'r').read()
except IOError, e:
    print 'Error: can\'t read %s' % _FILENAME
    if e.errno == errno.ENOENT:
        print 'Please download/move it to the current working directory.'
        sys.exit(1)
    raise
print 'Serving %d-byte %s (block size %d, %d blocks)' % (
    len(file_contents), _FILENAME, _BLOCK_SIZE,
    (len(file_contents) + _BLOCK_SIZE) // _BLOCK_SIZE)

handshake_thread = threading.Thread(target=handshake_loop,
                                    args=(handshake_sock,))
handshake_thread.start()
tftp_loop(tftp_sock, file_contents)
