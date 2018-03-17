#!/usr/bin/env python

__author__ = 'Scott Lamb'
__license__ = 'MIT'
__email__ = 'slamb@slamb.org'


import errno
import hikvision_tftpd
import socket
import string
import unittest
import platform
import sys


class TftpdTest(unittest.TestCase):
    _BLOCK_SIZE = 1468

    # From a packet capture.
    _TEST_RRQ = ('\x00\x01digicap.dav\x00'                  # request file digicap.dav
                 'octet\x00'                                # mode octet
                 'timeout\x005\x00'                         # RFC 2349 timeout = 5 seconds
                 'blksize\x00' + str(_BLOCK_SIZE) + '\x00')     # RFC 2348 block size = 1458

    _TEST_RRQ_DEFAULT_BLKSIZE = ('\x00\x01digicap.dav\x00'                  # request file digicap.dav
                 'octet\x00')                                # mode octet

    _LARGE_BUFFER_SIZE = 65536

    _BLKSIZE_OPTION = 'blksize\x00' + str(_BLOCK_SIZE) + '\x00'

    def setUp(self):
        self._server = None

    def tearDown(self):
        if self._server is not None:
            self._server.close()
            self._handshake_client.close()
            self._tftp_client.close()

    def _setup(self, data):
        self._server = hikvision_tftpd.Server(
                ('127.0.0.1', 0), ('127.0.0.1', 0), 'digicap.dav', data)
        self._handshake_client = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM)
        self._handshake_client.connect(
            self._server._handshake_sock.getsockname())
        self._tftp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._tftp_client.connect(self._server._tftp_sock.getsockname())

        # These tests run self._server._iterate() and then expect data to
        # be available immediately or not at all. But at least on OS X,
        # non-blocking operations don't already receive data that's already
        # been sent to this socket, so give some fudge time.
        self._tftp_client.settimeout(0.1)

    def _assert_no_data(self):
        try:
            d = self._tftp_client.recv(self._LARGE_BUFFER_SIZE)
        except socket.timeout:
            pass
        else:
            self.fail('expected nothing, got: %r' % d)

    def test_eaddrinuse(self):
        self._setup('')
        try:
            hikvision_tftpd.Server(self._server._handshake_sock.getsockname(),
                                   self._server._tftp_sock.getsockname(),
                                   'digicap.dav', '')
        except hikvision_tftpd.Error, e:
            self.assertTrue('in use' in e.message, 'Unexpected: %r' % e)
        else:
            self.fail('expected an error')

    def test_eaddrnotavail(self):
        try:
            # 192.0.2.0/24 is "TEST-NET", according to RFC 5737.
            # The local machine shouldn't have such an IP address.
            # (Okay, according to the RFCs, it shouldn't be using 192.0.0.128
            # either, but we do what we must.)
            hikvision_tftpd.Server(('192.0.2.1', 0), ('192.0.2.1', 0),
                                   'digicap.dav', '')
        except hikvision_tftpd.Error, e:
            self.assertTrue('not available' in e.message, 'Unexpected: %r' % e)
        else:
            self.fail('expected an error')

    # Skip check for user root not relevant on Windows Platform
    @unittest.skipIf(sys.platform.startswith('win'),
                     'Skip check for root permissions on Windows')
    def test_eaccess(self):
        try:
            hikvision_tftpd.Server(('127.0.0.1', 1), ('127.0.0.1', 3),
                                   'digicap.dav', '')
        except hikvision_tftpd.Error, e:
            self.assertTrue('permission' in e.message, 'Unexpected: %r' % e)
        else:
            self.fail('expected an error. '
                      '(did you run the tests as root? don\'t.)')


    def test_proper_handshake(self):
        self._setup('')
        self._handshake_client.send(hikvision_tftpd.HANDSHAKE_BYTES)
        self._server._iterate()
        pkt = self._handshake_client.recv(self._LARGE_BUFFER_SIZE)
        self.assertEqual(hikvision_tftpd.HANDSHAKE_BYTES, pkt)

    def test_bogus_handshake(self):
        self._setup('')
        self._handshake_client.send('asdf')
        self._server._iterate()
        self._assert_no_data()

    def test_one_block(self):
        data = string.letters
        self._setup(data)
        self._tftp_client.send(self._TEST_RRQ)
        self._server._iterate()
        pkt = self._tftp_client.recv(self._LARGE_BUFFER_SIZE)
        self.assertEqual('\x00\x06' + self._BLKSIZE_OPTION, pkt)

        # OACK ACK
        self._tftp_client.send('\x00\x04\x00\x00')
        self._server._iterate()
        pkt = self._tftp_client.recv(self._LARGE_BUFFER_SIZE)
        self.assertEqual('\x00\x03\x00\x01' + data, pkt)
        self._tftp_client.send('\x00\x03\x00\x01')
        self._server._iterate()
        self._assert_no_data()

    def test_two_block(self):
        blocksize = self._BLOCK_SIZE
        repetitions = 1 + blocksize // len(string.letters)
        data = string.letters * repetitions
        self._setup(data)

        # First packet.
        self._tftp_client.send(self._TEST_RRQ)
        self._server._iterate()
        pkt = self._tftp_client.recv(self._LARGE_BUFFER_SIZE)
        self.assertEqual('\x00\x06' + self._BLKSIZE_OPTION, pkt)

        # OACK ACK
        self._tftp_client.send('\x00\x04\x00\x00')
        self._server._iterate()
        pkt = self._tftp_client.recv(self._LARGE_BUFFER_SIZE)
        self.assertEqual('\x00\x03\x00\x01' + data[:blocksize], pkt)

        # Second packet.
        self._tftp_client.send('\x00\x04\x00\x01')
        self._server._iterate()
        pkt = self._tftp_client.recv(self._LARGE_BUFFER_SIZE)
        self.assertEqual('\x00\x03\x00\x02' + data[blocksize:], pkt)

        # No more packets.
        self._tftp_client.send('\x00\x04\x00\x02')
        self._server._iterate()
        self._assert_no_data()

    def test_full_block(self):
        blocksize = self._BLOCK_SIZE
        data = 'x' * blocksize
        self._setup(data)
        self._tftp_client.send(self._TEST_RRQ)
        self._server._iterate()
        pkt = self._tftp_client.recv(self._LARGE_BUFFER_SIZE)
        self.assertEqual('\x00\x06' + self._BLKSIZE_OPTION, pkt)

        # OACK ACK
        self._tftp_client.send('\x00\x04\x00\x00')
        self._server._iterate()
        pkt = self._tftp_client.recv(self._LARGE_BUFFER_SIZE)
        self.assertEqual('\x00\x03\x00\x01' + data, pkt)

        # Second packet (empty).
        self._tftp_client.send('\x00\x04\x00\x01')
        self._server._iterate()
        pkt = self._tftp_client.recv(self._LARGE_BUFFER_SIZE)
        self.assertEqual('\x00\x03\x00\x02', pkt)

        # No more packets.
        self._tftp_client.send('\x00\x04\x00\x02')
        self._server._iterate()
        self._assert_no_data()

    def test_full_block_default_blksize(self):
        blocksize = 512
        data = 'x' * blocksize
        self._setup(data)
        self._tftp_client.send(self._TEST_RRQ_DEFAULT_BLKSIZE)
        self._server._iterate()
        pkt = self._tftp_client.recv(self._LARGE_BUFFER_SIZE)
        self.assertEqual('\x00\x03\x00\x01' + data, pkt)

        # Second packet (empty).
        self._tftp_client.send('\x00\x04\x00\x01')
        self._server._iterate()
        pkt = self._tftp_client.recv(self._LARGE_BUFFER_SIZE)
        self.assertEqual('\x00\x03\x00\x02', pkt)

        # No more packets.
        self._tftp_client.send('\x00\x04\x00\x02')
        self._server._iterate()
        self._assert_no_data()

    def test_max_file_size(self):
        # The number of blocks in the file must fit within 16 bits.
        # The final block can't be full.
        max_blocks = 2**16 - 1
        max_size = self._BLOCK_SIZE * max_blocks - 1

        self._setup('x' * max_size)

        self._tftp_client.send(self._TEST_RRQ)
        self._server._iterate()
        self._server.close()

        self._setup('x' * (max_size + 1))
        self._tftp_client.send(self._TEST_RRQ)
        self.assertRaises(hikvision_tftpd.Error,
                          self._server._iterate)


if __name__ == '__main__':
    unittest.main()
