# passwd_check.py

Script to check if SSH connections can be established to given host:port using credentials specified in a file.

The file must contain either a list of credentials to check, one set ot username and password per line seperated by colons, or just a list of passwords one per line. This allows the usage of dictionary files from your OS.

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
usage: passwd_check.py [--help] (-h HOST | -hf HOSTFILE)
                       (-u USER | -uf USERFILE) (-p PASSWD | -pf PASSWDFILE)
                       [-l LOGFILE] [-q] [-t MAX_THREADS] [-v] [--version]

This is a program to test if SSH connections can be established using a list
of different credentials. If a(t least one) connection could be established by
the software the exit code of this program will be 1, if no connection could
be established it will return with exit code 0. This program is used for
testing if cloud users have changed the default passwords of user accounts
existing in VM images created by the Cloud provider. When specifying a
password file and a username file each username will be tested with every
password. These tests will be performed on every host! This may result in a
potentially large number of tests (# usernames x # passwords x # hosts). Be
aware of that.

optional arguments:
  --help                show this help message and exit
  -h HOST, --host HOST  Host/IP to connect
  -hf HOSTFILE, --hostfile HOSTFILE
                        File containig a list of hosts/IPs to test
  -u USER, --user USER  Username to connect with
  -uf USERFILE, --userfile USERFILE
                        File containing a list of usernames to use
  -p PASSWD, --passwd PASSWD
                        Password to test
  -pf PASSWDFILE, --passwdfile PASSWDFILE
                        File containing a list of passwords
  -l LOGFILE, --logfile LOGFILE
                        Append output also to a logfile
  -q, --quiet           Do not print anything to stdout
  -t MAX_THREADS, --threads MAX_THREADS
                        Maximum number of threads to use (default is 500)
  -v, --verbose         Set Verbosity (WARNING: output may contain passwords)
  --version             show program's version number and exit
```

## Contact
If you have any questions feel free to contact me at <niels@lrz.de>
