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
	return _dirAuths

_bwAuths = None
def get_bwauths():
	global config
	global _bwAuths
	if _bwAuths == None:
		_bwAuths = dict((k.lower(), v) for (k, v) in stem.directory.Authority.from_cache().items() if v.nickname.lower() in config['bwauths'])
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