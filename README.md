# passwd_check.py

<!-- TOC depthFrom:1 depthTo:6 withLinks:1 updateOnSave:1 orderedList:0 -->

- [passwd_check.py](#passwdcheckpy)
	- [Motivation](#motivation)
	- [Requirements](#requirements)
	- [Usage](#usage)
	- [Perform tests](#perform-tests)
		- [File format](#file-format)
			- [SSH port](#ssh-port)
		- [Log file](#log-file)
		- [Threads](#threads)
		- [Verbosity](#verbosity)
	- [Contact](#contact)

<!-- /TOC -->

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

## Perform tests
To use the password checker you must specify a host/a list of hosts, a username/a list of usernames and a password/a list of passwords. To specify a particular host, user or passwort you can use the ```--host```, ```--username```, or ```--passwd``` option. If you want to provides several lists containing a host, a user or a password per lines you can use the ```--hostfile```, ```--userfile```, or ```--passwdfile``` options respectively. When providing these files, each line will be treated as a host, user or password accordingly.

A typical command line for performing tests can look like:

```
./passwd_check.py --hostfile hosts.txt --userfile users.txt --passwdfile passwords.txt -vv
```


### File format
The files containing hosts, usernames or passwords need just to be simple text files with 1 entry per line. In the case of the userfile and the password file each line will be simply treated as a particular username or password respectively. Example of an userfile:

```
root
fallenbeck
username
admin
```

The same is valid for the hosts file but host lines will be preprocessed by checking if a port is specified.

#### SSH port
Usually port ```22``` is used during the connection tests. If you want to test using a different port you can specify it by appending the appropriate port to the host: ```localhost:2222```. This can be done when using the ```--host``` and the ```--hostfile``` option.

Example:

```
127.0.0.1:2222
localhost
```

### Log file
If you want to store the output to a file, you can specify a logfile with the ```-l```/```--logfile``` option. If this file does not exist, it will be created. If the file exists, the log output will be appended.


### Threads
The password checker supports threading. Each connection test will be performed as an individual thread. The default number of threads to use concurrently is ```500```. You can increase or decrease this number as you want. If you set it to ```0``` the number of maximum concurrent threads will be set to the number of tests to perform for maximum parallelity. Please note that your host operating system might kill threads in some case and the number of threads can be really huge. So it's always a good idea to provide a number greater than zero for the number of threads.

If you specify a maximum number of threads to use with ```-t```/```--threads``` this number will be treated as an upper bound: If you set the number to 500 (which is the default value) but only want to perform 100 tests, this number will be automatically decreased to 100. If your number of tests is greater than 500, only 500 connections will be created concurrently.


### Verbosity
If you want to see more information during the test runs you can set the level of verbosity by using ```-v```, ```-vv```, ```-vvv```, or ```-vvvv```. If you want to see nothing during the tests, you can switch into a quiet mode by using ```-q```/```--quiet```.

**Option**             | **PasswordCheck Log Level**  | **Paramiko Log Level**
:--------------------- | :--------------------------- | :---------------------
```-q```/```--quiet``` | CRITICAL                      | CRITICAL |
                       | WARN                          | CRITICAL |
```-v```               | INFO                          | CRITICAL |
```-vv```              | DEBUG                         | CRITICAL |
```-vvv```             | DEBUG                         | ERROR    |
```-vvvv```            | DEBUG                         | INFO     |
```-vvvvv```           | DEBUG                         | DEBUG    |

If you specify both the ```-q```/```--quiet``` option and one of the ```-v``` options, the quiet-Option will be overridden.




## Contact
If you have any questions feel free to contact me at <niels@lrz.de>
