#!/usr/bin/env python
"""
Unbrick a Hikvision device. Use as follows:

$ sudo ifconfig eth0:0 192.0.0.128
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

from __future__ import division

__author__ = 'Scott Lamb'
__license__ = 'MIT'
__email__ = 'slamb@slamb.org'

import errno
import os
import select
import socket
import struct
import sys
import time

HANDSHAKE_BYTES = struct.pack('20s', 'SWKH')
_SERVER_IP = '192.0.0.128'
_HANDSHAKE_SERVER_ADDR = (_SERVER_IP, 9978)
_TFTP_SERVER_ADDR = (_SERVER_IP, 69)
_FILENAME = 'digicap.dav'
_TIME_FMT = '%T'


class Error(Exception): pass


class Server(object):
    # See https://tools.ietf.org/html/rfc1350
    _TFTP_OPCODE_RRQ = 1
    _TFTP_OPCODE_DATA = 3
    _TFTP_OPCODE_ACK = 4
    _TFTP_RRQ_PREFIX = struct.pack('>h', _TFTP_OPCODE_RRQ) + _FILENAME + '\x00'
    _TFTP_ACK_PREFIX = struct.pack('>h', _TFTP_OPCODE_ACK)
    BLOCK_SIZE = 512

    def __init__(self, handshake_addr, tftp_addr, file_contents):
        self._file_contents = file_contents
        self._total_blocks = ((len(file_contents) + self.BLOCK_SIZE)
                              // self.BLOCK_SIZE)
        if self._total_blocks > 65535:
            raise Error('File is too big to serve with %d-byte blocks.'
                        % self.BLOCK_SIZE)
        self._handshake_sock = self._bind(handshake_addr)
        self._tftp_sock = self._bind(tftp_addr)
        print 'Serving %d-byte %s (block size %d, %d blocks)' % (
            len(file_contents), _FILENAME, self.BLOCK_SIZE, self._total_blocks)

    def _bind(self, addr):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(addr)
        except socket.error, e:
            if e.errno == errno.EADDRNOTAVAIL:
                raise Error(
                    ('Address %s:%d not available.\n\n'
                     'Try running:\n'
                     'linux$ ifconfig eth0:0 192.0.0.64\n'
                     'osx$   ifconfig en0 alias 192.0.0.64 255.255.255.0\n\n'
                     '(adjust eth0 or en0 to taste. see "ifconfig -a" output)')
                    % addr)
            if e.errno == errno.EADDRINUSE:
                raise Error(
                    ('Address %s:%d in use.\n'
                     'Make sure no other TFTP server is running.') % addr)
            if e.errno == errno.EACCES:
                raise Error(('No permission to bind to %s:%d.\n'
                             'Try running with sudo.') % addr)
            raise
        return sock

    def close(self):
        self._handshake_sock.close()
        self._tftp_sock.close()

    def run_forever(self):
        while True:
            self._iterate()

    def _iterate(self):
        r, _, _ = select.select(
            [self._handshake_sock, self._tftp_sock], [], [])
        if self._handshake_sock in r:
            self._handshake_read()
        if self._tftp_sock in r:
            self._tftp_read()

    def _handshake_read(self):
        pkt, addr = self._handshake_sock.recvfrom(len(HANDSHAKE_BYTES))
        now = time.strftime(_TIME_FMT)
        if pkt == HANDSHAKE_BYTES:
            self._handshake_sock.sendto(pkt, addr)
            print '%s: Replied to magic handshake request.' % now
        else:
            print '%s: received unexpected bytes %r from %s:%d' % (
                now, pkt.encode('hex'), addr[0], addr[1])

    def _tftp_read(self):
        try:
            pkt, addr = self._tftp_sock.recvfrom(65536)
        except socket.error, e:
            if e.errno == e.ENOTCONN:
                # socket was shutdown, as in shutdown().
                return
            raise
        now = time.strftime(_TIME_FMT)
        if pkt.startswith(self._TFTP_RRQ_PREFIX):
            print '%s: starting transfer' % now
            self._tftp_maybe_send(0, addr)
        elif pkt.startswith(self._TFTP_ACK_PREFIX):
            (block,) = struct.unpack(
                '>H', pkt[len(self._TFTP_ACK_PREFIX):])
            self._tftp_maybe_send(block, addr)
        else:
            print '%s: received unexpected bytes %r from %s:%d' % (
                now, pkt.encode('hex'), addr[0], addr[1])

    def _tftp_maybe_send(self, prev_block, addr):
        block = prev_block + 1
        start_byte = prev_block * self.BLOCK_SIZE
        if start_byte > len(self._file_contents):
            print '%s: done!' % time.strftime(_TIME_FMT)
            return
        block_data = self._file_contents[start_byte:start_byte+self.BLOCK_SIZE]
        pkt = (struct.pack('>hH', self._TFTP_OPCODE_DATA, block) + block_data)
        self._tftp_sock.sendto(pkt, addr)
        print '%s: %5d / %5d [%s]' % (
                time.strftime(_TIME_FMT), block, self._total_blocks,
                '#' * (53 * block // self._total_blocks))


if __name__ == '__main__':
    try:
        file_contents = open(_FILENAME, 'r').read()
    except IOError, e:
        print 'Error: can\'t read %s' % _FILENAME
        if e.errno == errno.ENOENT:
            print 'Please download/move it to the current working directory.'
            sys.exit(1)
        raise

    try:
        server = Server(_HANDSHAKE_SERVER_ADDR, _TFTP_SERVER_ADDR,
                        file_contents)
    except Error, e:
        print 'Error: %s' % e.message
        sys.exit(1)

    server.run_forever()
