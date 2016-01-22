Unbrick a Hikvision device. Use as follows:

Setup the expected IP address:

    linux$ sudo ifconfig eth0:0 192.0.0.128
    osx$   sudo ifconfig en0 alias 192.0.0.128 255.255.255.0

Download the firmware to use:

    $ curl -o digicap.dav <url of firmware>

Run the script:

    $ sudo ./hikvision_tftpd.py

Hit ctrl-C when done.

The Hikvision TFTP handshake (for both cameras and NVRs) is stupid but easy
enough. The client uses the address 192.0.0.64 and expects a TFTP server
running on address 192.0.0.128. It sends a particular packet to the server's
port 9978 from the client port 9979 and expects the server to echo it back.
Once that happens, it proceeds to send a tftp request (on the standard tftp
port, 69) for the file "digicap.dav", which it then installs. The tftp server
must reply from port 69 (unlike the tftpd package that comes with Debian).

This script handles both the handshake and the actual TFTP transfer.
The TFTP server is very simple but appears to be good enough.

See [discussion thread](https://www.ipcamtalk.com/showthread.php/3647-Hikvision-DS-2032-I-Console-Recovery).
