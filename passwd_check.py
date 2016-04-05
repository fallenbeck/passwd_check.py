#!/usr/bin/env python
# Used to check if cloud users have changed the passwords of the system
# accounts existing in the VM images provided by the Cloud provider.
#
# written by Niels Fallenbeck <niels@lrz.de>

from sys import exit, argv, version_info
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import os
import paramiko
from paramiko.ssh_exception import BadHostKeyException, AuthenticationException, SSHException
import argparse

# use logging
import logging
log_formatter = logging.Formatter('%(asctime)s [%(levelname)7s] %(message)s')
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.ERROR)

# by default, paramiko should also generate logging ouput in case of a
# critical error. in short, we do not want to see anything from paramiko
# by default. :)
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

class PasswordCheck:

	# program version :-)
	__version__ = "1.7"

	port = 22
	connections = 0

	# Data used for the tests
	users = []
	passwords = []
	hosts = []

	# Which credentials were used to connect
	successful_credentials = []

	# Number of threads to use for connection tests
	num_threads = 500

	# Should test started by __init__?
	# Useful when using as a stand-alone application. This switch will be set
	# to true when run directly from the command line


	# initialize the passwort test
	def __init__(self, started_from_cli = False):
		"""Initialization and running tests."""
		# Set up logging
		stdout = logging.StreamHandler()
		stdout.setFormatter(log_formatter)
		LOG.addHandler(stdout)

		if started_from_cli:
			LOG.debug("Script started from CLI; will parse arguments and run tests")
			# Read command line arguments
			self.parse_args()

			# Perform tests
			self.run_tests()

		else:
			LOG.debug("Script initialized programatically, set options an run tests manually")


	def parse_args(self):
		"""Parse the command line arguments."""
		description = "This is a program to test if SSH connections can be established using a list of	different credentials. If a(t least one) connection could be established by the	software the exit code of this program will be 1, if no connection could be established	it will return with exit code 0. This program is used for testing if cloud users have changed the default passwords of user accounts existing in VM images created by the Cloud provider. When specifying a password file and a username file each username will be tested with every password. These tests will be performed on every host! This may result in a potentially large number of tests (# usernames x # passwords x # hosts). Be aware of that."

		epilog = "%s %s, Python %d.%d.%d, Paramiko %s" % (__class__.__name__, PasswordCheck.__version__, version_info[0], version_info[1], version_info[2], paramiko.__version__)

		# Use a conflict handler so we can reuse the -v switch for verbosity
		# (it is usally used to display the help page)
		parser = argparse.ArgumentParser(description=description, epilog="Versions: %s" % epilog, conflict_handler="resolve")

		# Either the user must specify a host or a host file
		hostgroup = parser.add_mutually_exclusive_group(required=True)
		hostgroup.add_argument('-h', '--host', action='store', dest='host', help='Host/IP to connect', default=None)
		hostgroup.add_argument('-hf', '--hostfile', action='store', dest='hostfile', help='File containig a list of hosts/IPs to test', default=None)

		# Either the user must specify a username or a file containing usernames
		usergroup = parser.add_mutually_exclusive_group(required=True)
		usergroup.add_argument('-u', '--user', action='store', dest='user', help='Username to connect with', default=None)
		usergroup.add_argument('-uf', '--userfile', action='store', dest='userfile', help='File containing a list of usernames to use', default=None)

		# Either the user must specify a password or a passwordfile or a file
		# that contains a set of credentials <user>.<password> one per line
		passgroup = parser.add_mutually_exclusive_group(required=True)
		passgroup.add_argument('-p', '--passwd', action='store', dest='passwd', help='Password to test', default=None)
		passgroup.add_argument('-pf', '--passwdfile', action='store', dest='passwdfile', help='File containing a list of passwords', default=None)

		# Users are not allowed to used -q and -v at the same time
		verbositygroup = parser.add_mutually_exclusive_group(required=False)
		verbositygroup.add_argument('-v', '--verbose', action='count', dest='verbosity', help='Set verbosity (the more v\'s the more verbose)', default=0)
		verbositygroup.add_argument('-q', '--quiet', action='store_true', dest='quiet', help='Do not print anything to stdout')

		# Other options
		parser.add_argument('-l', '--logfile', action='store', dest='logfile', help='Append output also to a logfile')
		parser.add_argument('-t', '--threads', action='store', dest='max_threads', help='Maximum number of threads to use (default is %(default)s)', default=500)
		parser.add_argument('--version', action='version', version=epilog)

		# if an error occurs the help will be displayed automatically
		try:
			results = parser.parse_args()
		except:
			exit(2)

		# if quiet is set, set log level to highest level
		if results.quiet:
			LOG.setLevel(logging.CRITICAL)

		# set log level depending on verbosity
		# this overrides the silent flag
		elif results.verbosity == 0:
			LOG.setLevel(logging.WARN)
		elif results.verbosity == 1:
			LOG.setLevel(logging.INFO)
		elif results.verbosity == 2:
			LOG.setLevel(logging.DEBUG)
		elif results.verbosity == 3:
			LOG.setLevel(logging.DEBUG)
			logging.getLogger("paramiko").setLevel(logging.ERROR)
		elif results.verbosity == 4:
			LOG.setLevel(logging.DEBUG)
			logging.getLogger("paramiko").setLevel(logging.INFO)
		else:
			LOG.setLevel(logging.DEBUG)
			logging.getLogger("paramiko").setLevel(logging.DEBUG)

		# if a logfile has been specified change the basicConfig
		# to additionally print everything to that file
		if results.logfile is not None:
			fh = logging.FileHandler(results.logfile)
			fh.setFormatter(log_formatter)
			LOG.addHandler(fh)

		if results.verbosity >= 2:
			LOG.info("Will be very verbose (log messages will contain passwords!)")

		LOG.debug("Log levels are %s: %s, paramiko: %s" % (os.path.basename(argv[0]), logging.getLevelName(LOG.level), logging.getLevelName(logging.getLogger("paramiko").level)))

		# set the values of the groups
		if results.host is not None:
			self.hosts.append(results.host)
		if results.hostfile is not None:
			self.hosts = self._read_list_from_file(results.hostfile)

		if results.user is not None:
			self.users.append(results.user)
		if results.userfile is not None:
			self.users = self._read_list_from_file(results.userfile)

		if results.passwd is not None:
			self.passwords.append(results.passwd)
		if results.passwdfile is not None:
			self.passwords = self._read_list_from_file(results.passwdfile)

		# set the values read from the argument parser
		# if value is 0, then use the maximum number of threads
		# if value is > 0, value is an upper bound.
		# Either use this value (if you have more tasks than that)
		# or use the number of tasks
		self.num_threads = int(results.max_threads)
		if self.num_threads > 0:
			self.num_threads = min(self.num_threads, len(self.hosts) * len(self.users) * len(self.passwords))
		else:
			self.num_threads = len(self.hosts) * len(self.users) * len(self.passwords)

		LOG.debug("Set number of threads to %d" % (self.num_threads))

		LOG.debug("Successfully parsed command line arguments:\n%s" % (results))


	# read a list from a file and return contents as list
	def _read_list_from_file(self, filename):
		LOG.debug("Read file %s" % (filename))
		l = []
		try:
			with open(filename) as f:
				for line in f:
					# remove e.g. newlines
					line = line.strip()

					# if line is not empty add it to the list
					if line:
						l.append(line)

		except IOError:
			LOG.error("Could not open file %s" % (filename))
			exit(3)

		LOG.debug("Read %d lines" % (len(l)))

		# return list
		return l


	# Testing
	def run_tests(self):
		"""Perform tests and exit the program with a return code of 0 if
		everything went well or return code of 1 if connections could be
		established.
		It will exit with 1 if a connection could be established (== bad)
		If will exit with 0 if no connection could be esablished (== good)
		"""
		# LOG.info("Running %d tests (using %d threads)..." % (len(self.credentials), self.num_threads))
		LOG.info("Running %d tests..." % (len(self.hosts) * len(self.users) * len(self.passwords)))

		# run the connection tests and evaluate
		# using a certain number of threads
		self.try_to_connect()

		# exit the program with a particular exit code
		# If a connection could be established, exit code should be 1 (bad)
		# If no connection could be established, exit code should be 0 (good)
		if not len(self.successful_credentials):
			exit(0)
		else:
			exit(1)


	# iterate the credentials and try to establish SSH connections
	def try_to_connect(self):
		"""Use the credentials and try to establish SSH connections to
		the host.

		crecentials -- list of credentials to use
		"""
		LOG.debug("Performing %d tests to establish a SSH connection (using %d threads)" % (len(self.hosts) * len(self.users) * len(self.passwords), self.num_threads))

		with ThreadPoolExecutor(max_workers=self.num_threads) as e:
			for hostline in self.hosts:
				hostline = hostline.strip()
				try:
					host, port = hostline.split(":", 1)
				except:
					host = hostline
					port = 22

				try:
					port = int(port)
				except:
					port = 22

				LOG.debug("Host: %s:%d" % (host, port))

				for user in self.users:
					LOG.debug("Username: %s" % (user))

					for passwd in self.passwords:
						LOG.debug("Password: %s" % (passwd))

						# submit the job to the ThreadPoolExecutor
						e.submit(self.ssh_connect, user, passwd, host, port)


		LOG.debug("Successful connections: %d" % (len(self.successful_credentials)))


	def ssh_connect(self, user, passwd, host = "localhost", port = 22):
		"""Try to establish a single SSH connection to host:port
		using the provided user and passwd.

		user -- username
		passwd -- password
		host -- host to connect to
		port -- port to connect to
		"""
		LOG.debug("Trying to connect %s:%s@%s:%d ..." % (user, passwd, host, port))
		# Create paramiko ssh client
		ssh = paramiko.SSHClient()
		# Accept unknown host keys
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		try:
			# try to connect to the host
			# documenation to configuration options can be found on the
			# paramiko web page:
			# http://docs.paramiko.org/en/1.16/api/client.html
			ssh.connect(
				hostname = host,
				port = port,
				username = user,
				password = passwd,
				timeout = 1,
				allow_agent = False,
				look_for_keys = False,
				compress = False,
				sock = None,
				gss_auth = False,
				gss_kex = False,
				gss_deleg_creds = False,
				gss_host = None,
				banner_timeout = 0
			)

			# Add credentials which could be successfully used to connect
			self.successful_credentials.append("%s:%s" % (user, passwd))
			LOG.warning("Connection established to %s:%d using %s:%s" % (host, port, user, passwd))

		except Exception as e:
			LOG.debug("Could not establish connection")

		# Connection could be established.
		# Close the SSH connection in any case to prevent program hangs
		ssh.close()


if __name__ == "__main__":
	test = PasswordCheck(started_from_cli = True)
