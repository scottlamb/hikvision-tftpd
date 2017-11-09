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
enough. The client sends a particular packet to the server's port 9978 from
the client port 9979 and expects the server to echo it back.  Once that
happens, it proceeds to send a tftp request (on the standard tftp port, 69)
for a specific file, which it then installs. The tftp server must reply
from port 69 (unlike the tftpd package that comes with Debian).

This script handles both the handshake and the actual TFTP transfer.
The TFTP server is very simple but appears to be good enough.

Note the expected IP addresses and file name appear to differ by model. So far
there are two known configurations:

| client IP    | server IP    | filename      |
| ------------ | ------------ | ------------- |
| 192.0.0.64   | 192.0.0.128  | `digicap.dav` |
| 172.9.18.100 | 172.9.18.80  | `digicap.mav` |

This program defaults to the former. The latter requires commandline overrides:

    $ sudo ./hikvision_tftp.py --server-ip=172.9.18.80 --filename=digicap.mav

If nothing happens when your device restarts, your device may be expecting
another IP address. tcpdump may be helpful in diagnosing this:

    $ sudo tcpdump -i eth0 -vv -e -nn ether proto 0x0806
    tcpdump: listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
    16:21:58.804425 28:57:be:8a:aa:53 > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 60: Ethernet (len 6), IPv4 (len 4), Request who-has 172.9.18.80 tell 172.9.18.100, length 46
    16:22:00.805251 28:57:be:8a:aa:53 > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 60: Ethernet (len 6), IPv4 (len 4), Request who-has 172.9.18.80 tell 172.9.18.100, length 46

Feel free to open an issue for help.

See [discussion thread](https://www.ipcamtalk.com/showthread.php/3647-Hikvision-DS-2032-I-Console-Recovery).
