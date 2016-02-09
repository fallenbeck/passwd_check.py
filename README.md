# passwd_check.py

Script to check if SSH connections can be established to given host:port using credentials specified in a file.

The file contains a list of credentials to check, one set ot username and password per line seperated by colons.

## Motivation
This script was written to perform regular checks if users have changed the default passwords at their virtual machines provided by the Leibniz-Rechenzentrum (LRZ).

In our scenario we are not looking into the customers' VMs but check the passwords from outside using SSH connections.

## Requirements
This software was tested with Python 2.7.11 and Python 3.5.1.

You need to install the following package using `pip`:

* paramiko (tested with version 1.16.0)

I strongly recommend using a `virtualenv` to set up an environment to execute this script. Go for Python 3 if possible. (To install a Python 2.x environment use ```-p python``` instead of ```-p python3``` when creating the virtual environment.)

```
virtualenv -p python3 ~/.virtualenvs/passwd_check
source ~/.virtualenvs/passwd_check/bin/activate
pip install paramiko
```

## Usage
```
usage: passwd_check.py [--help] -f FILE -h HOST [-p PORT] [-q] [-u USER] [-v]
                       [--version]

This is a program to test if SSH connections can be established using a list
of different credentials. If a(t least one) connection could be established by
the software the exit code of this program will be 1, if no connection could
be established it will return with exit code 0. This program is used for
testing if cloud users have changed the default passwords of user accounts
existing in VM images created by the Cloud provider.

optional arguments:
  --help                show this help message and exit
  -f FILE, --file FILE  specify file containing the credentials (default:
                        credentials.txt)
  -h HOST, --host HOST  host/ip to connect
  -p PORT, --port PORT  port to connect (default: 22)
  -q, --quiet           do not print anything to stdout
  -u USER, --user USER  specify username to connect with (username will not be
                        parsed from input file)
  -v, --verbose         verbosity (WARNING: when using -vv or greater logging
                        output will contain passwords!)
  --version             show program's version number and exit
```

## Contact
If you have any questions feel free to contact me at <niels@lrz.de>