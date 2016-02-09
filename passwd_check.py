#!/usr/bin/env python
# Used to check if cloud users have changed the passwords of the system
# accounts existing in the VM images provided by the Cloud provider.
# 
# written by Niels Fallenbeck <niels@lrz.de>

from sys import exit, argv, version_info
import os
import paramiko
from paramiko.ssh_exception import BadHostKeyException, AuthenticationException, SSHException
import argparse

# use logging
import logging
logging.basicConfig(format='%(asctime)s [%(levelname)5s] %(message)s', level=logging.INFO)
# by default, paramiko should also generate logging ouput in case of an error
logging.getLogger("paramiko").setLevel(logging.ERROR)
LOG = logging.getLogger(__name__)

class PasswordCheck:

	# program version :-)
	__version__ = "0.3"

	host = "localhost"
	port = 22
	connections = 0
	credentials_file = None
	credentials = []

	# initialize the passwort test
	def __init__(self, credentials = "credentials.txt", hostname = "localhost", port = 22):
		"""Initialize the PasswortTest."""
		# Read command line arguments
		self.parse_args()

		# Read credentials from file
		self.credentials = self.read_credentials(self.credentials_file)

		# Perform tests
		self.run_tests()

	def parse_args(self):
		"""Parse the command line arguments."""
		description = "This is a program to test if SSH connections can be established using a\
		list of	different credentials. If a(t least one) connection could be established by the\
		software the exit code of this program will be 1, if no connection could be established\
		it will return with exit code 0.\
		This program is used for testing if cloud users have changed the default passwords of\
		user accounts existing in VM images created by the Cloud provider."

		epilog = "Versions: %s %s, Python %d.%d.%d, Paramiko %s" % (os.path.basename(argv[0]), PasswordCheck.__version__, version_info[0], version_info[1], version_info[2], paramiko.__version__)

		parser = argparse.ArgumentParser(description=description, epilog=epilog, conflict_handler="resolve")

		parser.add_argument('-f', '--file', action='store', dest='file', help='specify file containing the credentials (default: credentials.txt)', required=True)
		parser.add_argument('-h', '--host', action='store', dest='host', help='host/ip to connect', required=True)
		parser.add_argument('-p', '--port', action='store', dest='port', help='port to connect (default: %(default)s)', default="22", type=int)
		parser.add_argument('-q', '--quiet', action='store_true', dest='quiet', help='do not print anything to stdout', default=False)
		parser.add_argument('-v', '--verbose', action='count', dest='verbosity', help='verbosity (when using -vv logging information will contain passwords!)', default=0)
		parser.add_argument('--version', action='version', version='%s %s' % (os.path.basename(argv[0]),PasswordCheck.__version__))

		results = parser.parse_args()

		self.host = results.host
		self.port = results.port
		self.credentials_file = results.file

		# if quiet is set, set log level to highest level
		if results.quiet:
			LOG.setLevel(logging.CRITICAL)
		
		# set log level depending on verbosity
		# this overrides the silent flag
		elif results.verbosity == 0:
			LOG.setLevel(logging.INFO)
		elif results.verbosity == 1:
			LOG.setLevel(logging.DEBUG)
		elif results.verbosity == 2:
			LOG.setLevel(logging.DEBUG)
			# make paramiko more verbose
			logging.getLogger("paramiko").setLevel(logging.INFO)
		else:
			LOG.setLevel(logging.DEBUG)
			# display debug output from paramiko
			logging.getLogger("paramiko").setLevel(logging.DEBUG)

		if results.verbosity >= 2:
			LOG.info("Will be very verbose (log messages will contain passwords!)")

		LOG.debug("Set log level to %d" % (results.verbosity))
		LOG.debug("Successfully parsed command line arguments:\n%s" % (results))




	# read credentials from file and store them locally in self.credentials
	def read_credentials(self, filename):
		"""Read credentials from file and store them in a local list.
		The file has one set of credentials containing username and password
		per line seperated by a colon, e.g. user:passwd
	
		filename -- Name of file which holds the crecentials
		"""
		l = []

		with open(filename) as f:
			for line in f:
				l.append(line.strip())

		LOG.debug("Read %d credentials from file %s" % (len(l), filename))
		return l


	# Testing
	def run_tests(self):
		"""Perform tests and exit the program with a return code of 0 if
		everything went well or return code of 1 if connections could be
		established.
		"""
		LOG.info("Running %d tests ..." % (len(self.credentials)))
		
		# run the connection tests and evaluate
		success = self.evaluate(self.try_to_connect(self.credentials))

		# exit the program with a particular exit code
		if success:
			exit(0)
		else:
			exit(1)


	def evaluate(self, successful_credentials):
		"""Awaits a list of credentials which were used to successfully
		estblish an SSH connection. Evaluation will be made depending on
		the contents of this list.

		successful_credentials -- list of credentials
		"""
		# number of successfully used credentials
		num = len(successful_credentials)

		LOG.info("Successfully established SSH connections to %s:%s: %d" % (self.host, self.port, num))

		if num:
			# print out credentials which could be used to connect
			LOG.info(successful_credentials)
			return False
		else:
			return True


	# iterate the credentials and try to establish SSH connections
	def try_to_connect(self, credentials):
		"""Use the credentials and try to establish SSH connections to
		the host.

		crecentials -- list of credentials to use
		"""
		LOG.debug("Trying list of %d credentials to establish SSH connection" % (len(credentials)))
		# Keep track of successfully used credentials
		successful_credentials = []

		for cred in credentials:
			# split up each line in username and password
			user, passwd = cred.split(':', 1)
			LOG.debug("Testing %s:%s" % (user, passwd))
			if self.ssh_connect(user = user, passwd = passwd, host = self.host, port = self.port):
				successful_credentials.append(cred)

		LOG.debug("Successful connections: %d" % (len(successful_credentials)))
		return successful_credentials


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
		except Exception as e:
			LOG.debug("Could not establish connection")
			return False

		# Connection could be established.
		# Close the SSH connection in any case to prevent program hangs
		ssh.close()
		LOG.debug("Connection successfully established")
		return True


if __name__ == "__main__":
	test = PasswordCheck()
