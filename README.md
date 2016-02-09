# passwd_check.py

Script to check if SSH connections can be established to given host:port
using credentials specified in a file.

The file contains a list of credentials to check, one set ot username and
password per line seperated by colons.

## Motivation
This script was written to perform regular checks if users have changed the
default passwords at their virtual machines provided by the Leibniz-Rechenzentrum (LRZ).

## Contact
If you have any questions feel free to contact me at <niels@lrz.de>