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
	__version__ = "1.5"

	host = "localhost"
	port = 22
	connections = 0
	credentials_file = None
	credentials = []
	user = None

	# Number of threads
	# 0 means auto and will use 500 threads
	num_threads = 500

	# Which credentials were used to connect
	credentials = []
	successful_credentials = []

	# initialize the passwort test
	def __init__(self, credentials, hostname, port = 22):
		"""Initialize the PasswortTest."""
		# Set up logging
		stdout = logging.StreamHandler()
		stdout.setFormatter(log_formatter)
		LOG.addHandler(stdout)

		# Read command line arguments
		self.parse_args()

		# Read credentials from file
		self.read_credentials(self.credentials_file)

		# Perform tests
		self.run_tests()

	def parse_args(self):
		"""Parse the command line arguments."""
		description = "This is a program to test if SSH connections can be established using a list of	different credentials. If a(t least one) connection could be established by the	software the exit code of this program will be 1, if no connection could be established	it will return with exit code 0. This program is used for testing if cloud users have changed the default passwords of user accounts existing in VM images created by the Cloud provider."

		epilog = "%s %s, Python %d.%d.%d, Paramiko %s" % (__class__.__name__, PasswordCheck.__version__, version_info[0], version_info[1], version_info[2], paramiko.__version__)

		parser = argparse.ArgumentParser(description=description, epilog="Versions: %s" % epilog, conflict_handler="resolve")

		parser.add_argument('-f', '--file', action='store', dest='file', help='File containing the credentials', required=True)
		parser.add_argument('-h', '--host', action='store', dest='host', help='Host/IP to connect', required=True)
		parser.add_argument('-l', '--logfile', action='store', dest='logfile', help='Append output also to a logfile', required=False)
		parser.add_argument('-p', '--port', action='store', dest='port', help='Port to connect to (default: %(default)s)', default="22", type=int)
		parser.add_argument('-q', '--quiet', action='store_true', dest='quiet', help='Do not print anything to stdout', default=False)
		parser.add_argument('-t', '--threads', action='store', dest='threads', help='Number of threads to use (default is 500)', default=500)
		parser.add_argument('-u', '--user', action='store', dest='user', help='Username to connect with (username will not be parsed from input file)', default=None)
		parser.add_argument('-v', '--verbose', action='count', dest='verbosity', help='Verbosity (WARNING: when using -vvv or greater logging output will contain passwords!)', default=0)
		parser.add_argument('--version', action='version', version=epilog)

		# if an error occurs the help will be displayed automatically
		try:
			results = parser.parse_args()
		except:
			exit(1)

		# set the values read from the argument parser
		self.host = results.host
		self.port = results.port
		self.credentials_file = results.file
		self.user = results.user
		self.num_threads = int(results.threads)

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
		LOG.debug("Successfully parsed command line arguments:\n%s" % (results))


	# read credentials from file and store them locally in self.credentials
	def read_credentials(self, filename):
		"""Read credentials from file and store them in a local list.
		The file has one set of credentials containing username and password
		per line seperated by a colon, e.g. user:passwd

		filename -- Name of file which holds the crecentials
		"""
		with open(filename) as f:
			for line in f:
				try:
					# strip line breaks and stuff
					line = line.strip()

					# process the data read
					if not self.user:
						# if no default user has been set (using -u/--username)
						# the user name will be parsed from the current line of
						# the credentials file
						user, passwd = line.split(':', 1)
					else:
						# if a default user has been set
						# the complete line from the credentials file will be
						# treated as password
						user = self.user
						passwd = line

					# perform a sanity check and store it to the global
					# credentials[]
					if user.strip() and passwd.strip():
						# continue only if user and password are not empty
						LOG.debug("Adding %s:%s" % (user, passwd))
						self.credentials.append("%s:%s" % (user, passwd))
					else:
						LOG.warning("Empty user or password string in line: %s" % (line))

				except Exception as e:
					LOG.error("Error while parsing line: %s" % (line))

		LOG.debug("Read %d credentials from file %s" % (len(self.credentials), filename))


	# Testing
	def run_tests(self):
		"""Perform tests and exit the program with a return code of 0 if
		everything went well or return code of 1 if connections could be
		established.
		"""
		# LOG.info("Running %d tests (using %d threads)..." % (len(self.credentials), self.num_threads))
		LOG.info("Running %d tests..." % (len(self.credentials)))

		# run the connection tests and evaluate
		# using a certain number of threads
		self.try_to_connect()

		# exit the program with a particular exit code
		if self.evaluate:
			exit(0)
		else:
			exit(1)


	def evaluate(self):
		"""Awaits a list of credentials which were used to successfully
		estblish an SSH connection. Evaluation will be made depending on
		the contents of this list.

		successful_credentials -- list of credentials
		"""
		# number of successfully used credentials
		num = len(self.successful_credentials)

		LOG.info("Successfully established SSH connections to %s:%s: %d" % (self.host, self.port, num))

		if num:
			# print out credentials which could be used to connect
			LOG.warning("Connection established to %s using %s" % (self.host, ",".join(successful_credentials)))
			return False
		else:
			return True


	# iterate the credentials and try to establish SSH connections
	def try_to_connect(self):
		"""Use the credentials and try to establish SSH connections to
		the host.

		crecentials -- list of credentials to use
		"""
		# if num_credentials == 0 (auto) set the number of workers to the
		# number of credentials to test
		if self.num_threads == 0:
			self.num_threads = len(self.credentials)

		LOG.debug("Trying list of %d credentials to establish SSH connection (using %d threads)" % (len(self.credentials), self.num_threads))

		with ThreadPoolExecutor(max_workers=self.num_threads) as e:
			for cred in self.credentials:
				# split up each line in username and password
				user, passwd = cred.strip().split(':', 1)

				# submit the job to the ThreadPoolExecutor
				e.submit(self.ssh_connect, user, passwd, self.host, self.port)

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
		except Exception as e:
			LOG.debug("Could not establish connection")
			return False

		# Connection could be established.
		# Close the SSH connection in any case to prevent program hangs
		ssh.close()
		self.successful_credentials.append("%s:%s" % (user, passwd))
		LOG.debug("Connection successfully established using")
		return True


if __name__ == "__main__":
	test = PasswordCheck(credentials = "credentials.txt", hostname = "localhost")
