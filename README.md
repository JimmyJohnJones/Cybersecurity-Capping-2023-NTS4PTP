This is a an implementation of NTS in Python 3.

This code is based on Daniel Franke's hackathon code which implemented
parts of the NTS protocol: "Quick and dirty implementation of [Network
Time Security](https://github.com/dfoxfranke/nts) for the IETF 101
hackathon" which are in the Public domain.

Christer Weinigel <christer@weinigel.se> made some fixes to the
implementation and added a NTSKE server, a NTS/UDP server and a
NTS/UDP client.

Prerequisites
=============

Debian 10 or Ubuntu 18.04.  Debian 9 and Ubuntu 16.04 do not work due
to the openssl libraries being too old.

Install the following packages:

 sudo apt-get install git gcc binutils cmake libssl-dev python3-cffi

Custom Python
-------------

The NTS server and client need a modified version of Python 3 to work.
The reason for this is that the NTS protocol uses the key exporter
functions of OpenSSL and those are not supported in the stock OpenSSL
wrapper in Python 3.

Install some pacages needed to build Python 3:

 sudo apt-get install git build-essential cmake pkg-config libssl-dev libffi-dev libz-dev wget

Clone the modified Python 3 repository:

 git clone -b export_keying_material-3.7.4 https://github.com/Netnod/cpython.git

 cd cpython
 LDFLAGS=-Wl,-rpath,$PREFIX/lib ./configure --prefix=/opt/python-nts
 make -j`nproc`
 sudo make install
 sudo mkdir -p /opt/python-nts/ssl
 sudo ln -sf /etc/ssl/ca-certificates.crt /opt/python-nts/ssl/cert.pem
 sudo ln -sf /etc/ssl/certs /opt/python-nts/ssl/certs
 sudo /opt/python-nts/bin/python3 -m pip install cffi

Checking out
============

Clone the repository:

 git clone --recursive [https://github.com/JimmyJohnJones/Cybersecurity-Capping-2023-NTS4PTP.git](https://github.com/JimmyJohnJones/Cybersecurity-Capping-2023-NTS4PTP.git)

Testing the Python implementation
=================================

I've tested this implementation on Ubuntu 18.04.  The scripts require
Python 3.6, even though they are written to be compatible with Python
2.7.  I haven't figured out why Python 2.7 doesn't work yet.

Warning: don't remove the assert sys.version_info[0] == 3 from the
files.  It might seem like it's working, but the SSL.Connection will
return corrupt data with some NTS servers.

Change directory to the top of the nts-python tree:

 cd Cybersecurity-Capping-2023-NTS4PTP
 ./build.sh

To start the NTSKE server, open a terminal and run:

 /opt/python-nts/bin/python3 ntske_server.py

The server uses server.ini for its configuration.  The default is for
the NTSKE server to listen on TCP port 4446.  The master keys are
stored in the directory "server_keys".  If no master key exists, the
NTSKE server will create a new master key.

To start the NTP/UDP server, open a terminal and run:

 /opt/python-nts/bin/python3 ntsts_server.py

The server uses the file "server.ini" for its configuration.  The
default is for the NTSKE server to listen on TCP port 4123.

Run the NTSKE client to talk to the NTSKE server and save the results
to the file "client.ini" and not perform certicate verification (-v).

 /opt/python-nts/bin/python3 ntske_client.py -v localhost 4460

Run the NTS client to talk to the NTS server and get a timestamped
packet back.

 /opt/python-nts/bin/python3 ntsts_client.py

If you want to talk to a different NTS server than the one specified
in client.ini you can specify the NTS server on the command line:

 python ntsts_client.py host port

If you want to rotate the master key, run server_helper.py:

 /opt/python-nts/bin/python3 server_helper.py

This will create a new key in the server_keys directory which will be
read by ntske-server.py or nts-server.py on the next request.
