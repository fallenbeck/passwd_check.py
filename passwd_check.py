#!/usr/bin/env python
# Used to check if cloud users have changed the passwords of the system
# accounts existing in the VM images provided by the Cloud provider.
#
# written 2016 by Niels Fallenbeck <niels@lrz.de>

from sys import exit, argv, version_info
import concurrent.futures
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
	"""
	This is the main class which covers functionality to perform SSH connection
	tests. It has been designed to automatically test a potentially huge number
	of hosts with a potentially huge number of different credentials.
	Background is that we wanted to perform automatic security tests at a
	couple of customers VMs in our Cloud infrastructure.
	"""

	# program version :-)
	__version__ = "2.1"

	port = 22
	connections = 0

	# Data used for the tests
	users = []
	passwords = []
	hosts = []

	# Which credentials were used to connect
	successful_connections = {}

	# Number of threads to use for connection tests
	num_threads = 500

	# Should test started by __init__?
	# Useful when using as a stand-alone application. This switch will be set
	# to true when run directly from the command line
	# Has program started directly from the CLI?
	cli_mode = False


	# initialize the passwort test
	def __init__(self, started_from_cli = False):
		"""
		Initialization and running tests.
		When started from the CLI the script will end with a exit(n) where n is the
		exit code. If not started from the CLI (when used programatically) this
		program will not exit but return the exit code n (but keeps running).

		started_from_cli -- switch to indicate if script has been started from the CLI
		"""
		# Set up logging
		stdout = logging.StreamHandler()
		stdout.setFormatter(log_formatter)
		LOG.addHandler(stdout)

		# set flag if program has been started from the command line
		self.cli_mode = started_from_cli

		if self.cli_mode:
			LOG.debug("Program started from CLI; will parse arguments and run tests")
			# Read command line arguments
			self.parse_args()

			# Perform tests
			self.run_tests()

		else:
			LOG.debug("Program initialized programatically, set options an run tests manually")


	def parse_args(self):
		"""
		Parse the command line arguments.
		"""
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

		# set the log level
		if results.quiet:
			self.set_verbosity(-1)
		else:
			self.set_verbosity(results.verbosity)

		# if a logfile has been specified change the basicConfig
		# to additionally print everything to that file
		if results.logfile is not None:
			fh = logging.FileHandler(results.logfile)
			fh.setFormatter(log_formatter)
			LOG.addHandler(fh)

		if results.verbosity >= 2:
			LOG.info("Will be very verbose (log messages will contain passwords!)")

		# set the values of the groups
		if results.host is not None:
			self.hosts.append(results.host)
		if results.hostfile is not None:
			self.load_hosts_from_file(results.hostfile)

		if results.user is not None:
			self.users.append(results.user)
		if results.userfile is not None:
			self.load_usernames_from_file(results.userfile)

		if results.passwd is not None:
			self.passwords.append(results.passwd)
		if results.passwdfile is not None:
			self.load_passwords_from_file(results.passwdfile)

		# set the values read from the argument parser
		# set the upper boundary of the number of tasks to use
		# 0 means there are no limits (which is not recommended)
		self.set_max_threads(results.max_threads)

		LOG.debug("Successfully parsed command line arguments:\n%s" % (results))


	# Setting values
	def set_verbosity(self, verbosity):
		"""
		Set the verbosity used for log output.
		If the quiet switch was set, you will receive -1 as verbosity else
		verbosity will be represent the number of -v's a user has specified.

		verbosity -- Verbosity to use (from -1 to 5)
		"""
		# if quiet is set, set log level to highest level
		if verbosity < 0:
			LOG.setLevel(logging.CRITICAL)

		# set log level depending on verbosity
		# this overrides the silent flag
		elif verbosity == 0:
			LOG.setLevel(logging.WARN)
		elif verbosity == 1:
			LOG.setLevel(logging.INFO)
		elif verbosity == 2:
			LOG.setLevel(logging.DEBUG)
		elif verbosity == 3:
			LOG.setLevel(logging.DEBUG)
			logging.getLogger("paramiko").setLevel(logging.ERROR)
		elif verbosity == 4:
			LOG.setLevel(logging.DEBUG)
			logging.getLogger("paramiko").setLevel(logging.INFO)
		else:
			LOG.setLevel(logging.DEBUG)
			logging.getLogger("paramiko").setLevel(logging.DEBUG)

		LOG.debug("Updated log levels to %s: %s, paramiko: %s" % (os.path.basename(argv[0]), logging.getLevelName(LOG.level), logging.getLevelName(logging.getLogger("paramiko").level)))

	def set_max_threads(self, max_threads):
		"""
		Set the maximum number of threads to be used to perform the security
		tests. Note that this sets the upper boundary of the number of threads.
		During the scan operation this is the maximum number of workers running
		at the same time. But the software could always use less. :-)
		A value of 0 means that no upper limit exists. Be careful with this
		because it can render your computer unresponsive when you test a
		huge number of hosts, usernames and passwords at once.

		num_threads -- number of threads to use, 0 means no limits
		"""
		# set the values read from the argument parser
		# if value is 0, then use the maximum number of threads
		# if value is > 0, value is an upper bound.
		# Either use this value (if you have more tasks than that)
		# or use the number of tasks
		self.num_threads = int(max_threads)

		LOG.debug("Set maximum number of threads to %d" % (max_threads))


	# Programatically use
	def load_usernames_from_file(self, filename):
		"""
		Load a list of usernames from a file that should be taken into
		consideration during the tests.
		"""
		usernames = PwckHelper.read_list_from_file(filename)
		LOG.debug("Loaded {} usernames from file {}".format(len(usernames), filename))
		self.users = usernames

	def load_passwords_from_file(self, filename):
		"""
		Load a list of passwords from a file that should be used during testing.
		"""
		passwords = PwckHelper.read_list_from_file(filename)
		LOG.debug("Loaded {} passwords from file {}".format(len(passwords), filename))
		self.passwords = passwords

	def load_hosts_from_file(self, filename):
		"""
		Load a list of hosts/ips from a file that should be tested.
		"""
		hosts = PwckHelper.read_list_from_file(filename)
		LOG.debug("Loaded {} hosts/addresses from file {}".format(len(hosts), filename))
		self.hosts = hosts

	def set_hosts_to_scan(self, list_of_ips):
		"""
		Set a list of hosts/ips to be scanned.
		"""
		LOG.debug("Set {} hosts/addresses to scan".format(len(list_of_ips)))
		self.hosts = list_of_ips

	def get_successful_connections(self):
		"""
		Returns the dict of successful connections:
			host:port -> username:password
		"""
		LOG.debug("Return dict with {} successful connections".format(len(self.successful_connections)))
		return self.successful_connections



	# Testing
	def run_tests(self):
		"""
		Perform tests and exit the program with a return code of 0 if
		everything went well or return code of 1 if connections could be
		established.
		It will exit with >=1 if a connection could be established (== bad)
		If will exit with 0 if no connection could be esablished (== good)
		"""
		LOG.info("Running %d tests..." % (len(self.hosts) * len(self.users) * len(self.passwords)))

		# run the connection tests and evaluate
		# using a certain number of threads
		self.try_to_connect()

		# exit the program with a particular exit code
		# If a connection could be established, exit code should be > 0 (bad)
		# If no connection could be established, exit code should be 0 (good)
		return self.evaluate(len(self.successful_connections))


	def evaluate(self, code, max_code = 255):
		"""
		This method is used to handle the return code. A return code of 0
		means that everything went well while a code != 0 points to either
		a problem or an unwanted result.
		If the program has been started from the command line it exits with
		the given code used as retval, if it has been started programmatically
		the code is returned by this function.

		code -- exit code you want to return or quit with
		max_code -- maximum exit code
		"""
		LOG.debug("Evaluate the code %d (max_code = %d)" % (code, max_code))
		# set the maximum return code
		retval = min(max_code, code)

		if self.cli_mode:
			exit(retval)
		else:
			return(retval)


	# iterate the credentials and try to establish SSH connections
	def try_to_connect(self):
		"""
		Use the credentials and try to establish SSH connections to
		the host.
		"""
		LOG.debug("Performing %d tests to establish a SSH connection (using %d threads)" % (len(self.hosts) * len(self.users) * len(self.passwords), self.num_threads))

		# determine the needed size of the thread pool but keep the upper
		# limit into consideration
		num_workers = 0
		if self.num_threads > 0:
			num_workers = min(self.num_threads, len(self.hosts) * len(self.users) * len(self.passwords))
		else:
			num_workers = len(self.hosts) * len(self.users) * len(self.passwords)

		LOG.debug("Using thread pool with {} workers".format(num_workers))

		futures = []

		with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as e:
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
						futures.append(e.submit(self.ssh_connect, user, passwd, host, port))


		LOG.debug("Waiting for tasks to complete")
		results = concurrent.futures.wait(futures, timeout=3)
		LOG.debug("{} tasks completed".format(len(results.done)))

		LOG.debug("Successful connections: %d\n%s" % (len(self.successful_connections), self.successful_connections))


	def ssh_connect(self, user, passwd, host = "localhost", port = 22):
		"""
		Try to establish a single SSH connection to host:port
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
			self.successful_connections["%s:%d" % (host, port)] = "%s:%s" % (user, passwd)
			LOG.warning("Connection established to %s:%d using %s:%s" % (host, port, user, passwd))

		except Exception as e:
			LOG.debug("Could not establish connection")

		# Connection could be established.
		# Close the SSH connection in any case to prevent program hangs
		ssh.close()




class PwckHelper:
	"""
	This class is intended to provide helper functions which are not related
	to the SSH password scan process.
	"""

	@staticmethod
	def read_list_from_file(filename):
		"""
		Read the contents of a file and return it as a list.
		Each line of the file will be treaded as a list item.

		filename -- name of the file to read
		"""
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
			pass

		# return list
		return l




if __name__ == "__main__":
	test = PasswordCheck(started_from_cli = True)
