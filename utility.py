#!/usr/bin/env python3

import time
import urllib
import datetime

import stem.directory
import stem.descriptor
import stem.descriptor.remote
import stem.util.conf
import stem.util.enum

config = {'bwauths': []}
def set_config(c):
	global config
	config = c

_dirAuths = None
def get_dirauths():
	global _dirAuths
	if _dirAuths == None:
		#Remove any BridgeAuths
		_dirAuths = dict((k.lower(), v) for (k, v) in stem.directory.Authority.from_cache().items() if v.v3ident)
		# Update IP addresses and other information that has changed since stem cut a release
		del _dirAuths['faravahar']
		_dirAuths['moria1'].address = "128.31.0.24"
		_dirAuths['moria1'].or_port = 9201
		_dirAuths['moria1'].dir_port = 9231
		_dirAuths['moria1'].v3ident = "F533C81CEF0BC0267857C99B2F471ADF249FA232"
		_dirAuths['moria1'].fingerprint = "1A25C6358DB91342AA51720A5038B72742732498"
		_dirAuths['dizum'].address = "45.66.35.11"
	return _dirAuths

_bwAuths = None
def get_bwauths():
	global config
	global _bwAuths
	if _bwAuths == None:
		_bwAuths = dict((k.lower(), v) for (k, v) in get_dirauths().items() if v.nickname.lower() in config['bwauths'])
	return _bwAuths

# How to grab a vote or consensus with stem:
"""
import stem.descriptor.remote
authority = stem.descriptor.remote.get_authorities()['moria1']
downloader = stem.descriptor.remote.DescriptorDownloader(fall_back_to_authority = False, document_handler = stem.descriptor.DocumentHandler.DOCUMENT)
vote = downloader.query('/tor/status-vote/current/authority.z', default_params = False, endpoints=[(authority.address, authority.dir_port)]).run()[0]
"""

downloader = stem.descriptor.remote.DescriptorDownloader(
	timeout = 30,
	fall_back_to_authority = False,
	document_handler = stem.descriptor.DocumentHandler.DOCUMENT,
)

def get_consensuses():
	"""
	Provides a mapping of directory authority nicknames to their present consensus.

	:returns: tuple of the form ({authority => consensus}, issues, runtimes)
	"""

	return _get_documents('consensus', '/tor/status-vote/current/consensus-microdesc.z')


def get_votes():
	"""
	Provides a mapping of directory authority nicknames to their present vote.

	:returns: tuple of the form ({authority => vote}, issues, runtimes)
	"""

	return _get_documents('vote', '/tor/status-vote/current/authority.z')


# Multithreading
import concurrent.futures

def _validate_from_one_vote(authority, recv_authority):
	_downloader = stem.descriptor.remote.DescriptorDownloader(
		timeout = 30,
		retries = 5,
		fall_back_to_authority = False,
		document_handler = stem.descriptor.DocumentHandler.DOCUMENT,
	)
	query = _downloader.query(
		'/tor/status-vote/current/%s.z' % authority.v3ident,
		endpoints = [stem.DirPort(recv_authority.address, recv_authority.dir_port)],
		default_params = False,
		start = False
	)
	# Re-add the .z suffix per #25782
	query.resource = query.resource + ".z"
	exception = ""
	for i in range(5):
		try:
			recv_vote = query.run()[0]
			return ("OK", recv_vote)
		except Exception as exc:
			exception = str(exc)
			time.sleep(10)
			continue
	return (exception, "")


def validate_votes():
	"""
	Confirm that there is no discrepency within votes.

	:returns: dict of the form {sender => {receiver => {URL, err}}}
	"""
	validation = {}
	validation_queue = {}
	validation_result = {}
	with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
		for (nickname, authority) in get_dirauths().items():
			if authority.v3ident is None:
				continue
			validation[nickname] = {}
			validation_queue[nickname] = {}
			validation_result[nickname] = {}
			for (recv_nickname, recv_authority) in get_dirauths().items():
				if recv_authority.v3ident is None:
					continue
				validation_queue[nickname][recv_nickname] = executor.submit(_validate_from_one_vote, authority, recv_authority)
		for (nickname, authority) in get_dirauths().items():
			if authority.v3ident is None:
				continue
			for (recv_nickname, recv_authority) in get_dirauths().items():
				if recv_authority.v3ident is None:
					continue
				validation[nickname][recv_nickname] = validation_queue[nickname][recv_nickname].result()
		for (nickname, authority) in get_dirauths().items():
			if authority.v3ident is None:
				continue
			for (recv_nickname, recv_authority) in get_dirauths().items():
				if recv_authority.v3ident is None:
					continue
				url = 'http://' + str(recv_authority.address) + ':' + str(recv_authority.dir_port) + \
					'/tor/status-vote/current/%s.z' % authority.v3ident
				if validation[nickname][recv_nickname][0] != "OK":
					validation_result[nickname][recv_nickname] = (url, validation[nickname][recv_nickname][0])
				elif validation[nickname][nickname][0] != "OK":
					validation_result[nickname][recv_nickname] = (url, "Unable to validate the vote with the sender")
				elif validation[nickname][nickname] != validation[nickname][recv_nickname]:
					validation_result[nickname][recv_nickname] = (url, "Discrepency detected")
				else:
					validation_result[nickname][recv_nickname] = (url, "OK")
	return validation_result


def _get_documents(label, resource):
	documents, issues, runtimes = {}, [], {}

	for (nickname, authority) in get_dirauths().items():
		if authority.v3ident is None:
			continue	# not a voting authority

		query = downloader.query(
			resource,
			endpoints = [stem.DirPort(authority.address, authority.dir_port)],
			default_params = False,
			start = False
		)
		# Re-add the .z suffix per #25782
		query.resource = query.resource + ".z"

		try:
			start_time = time.time()
			documents[nickname] = query.run()[0]
			runtimes[nickname] = time.time() - start_time
		except Exception as exc:
			if label == 'vote':
				# try to download the vote via the other authorities

				v3ident = authority.v3ident

				query = downloader.query(
					'/tor/status-vote/current/%s.z' % v3ident,
					default_params = False,
				)

				query.run(True)

				if not query.error:
					documents[nickname] = list(query)[0]
					continue

			issues.append(('AUTHORITY_UNAVAILABLE', label, authority, query.download_url, exc))

	return documents, issues, runtimes

def get_clockskew():
	clockskew = {}
	for (nickname, authority) in get_dirauths().items():
		authority_address = "http://" + str(authority.address) + ":" + str(authority.dir_port) + "/tor/keys/authority.z"
		try:
			startTimeStamp = datetime.datetime.utcnow()
			startTime = time.time()
			f = urllib.request.urlopen(authority_address, timeout=30)
			h = f.getheader('date')
			if h:
				clockskew[nickname] = datetime.datetime.strptime(h, '%a, %d %b %Y %H:%M:%S %Z')
			else:
				print("Could not get clockskew for ", nickname)
				continue
			processing = time.time() - startTime
			if processing > 5:
				clockskew[nickname] -= datetime.timedelta(seconds=(processing / 2))
			clockskew[nickname] -= startTimeStamp
			clockskew[nickname] = clockskew[nickname].total_seconds()
		except Exception as e:
			print("Clockskew Exception:", e)
			continue
	return clockskew

def unix_time(dt):
    return (dt - datetime.datetime.utcfromtimestamp(0)).total_seconds() * 1000.0

def ut_to_datetime(ut):
	return datetime.datetime.utcfromtimestamp(ut / 1000)

def ut_to_datetime_format(ut):
	return consensus_datetime_format(ut_to_datetime(ut))

def consensus_datetime_format(dt):
	return dt.strftime("%Y-%m-%d-%H-%M-%S")

class FileMock():
	def __init__(self):
		pass
	def write(self, str):
		pass

if __name__ == "__main__":
	skew = get_clockskew()
	for c in skew:
		print(c, skew[c])
