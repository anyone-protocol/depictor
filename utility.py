#!/usr/bin/env python

import time
import urllib
import datetime

import stem.descriptor
import stem.descriptor.remote
import stem.util.conf
import stem.util.enum

from stem.util.lru_cache import lru_cache

@lru_cache()
def get_dirauths():
	#Remove any BridgeAuths
	return dict((k.lower(), v) for (k, v) in stem.descriptor.remote.get_authorities().items() if v.v3ident)

@lru_cache()
def get_bwauths():
	return dict((k.lower(), v) for (k, v) in stem.descriptor.remote.get_authorities().items() if v.is_bandwidth_authority)

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

	return _get_documents('consensus', '/tor/status-vote/current/consensus.z')


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
			endpoints = [(authority.address, authority.dir_port)],
			default_params = False,
			start = False
		)
		# Re-add the .z suffix per #25782
		query.resource = query.resource + ".z"

		try:
			start_time = time.time()
			documents[nickname] = query.run()[0]
			runtimes[nickname] = time.time() - start_time
		except Exception, exc:
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
		authority_address = "http://" + str(authority.address) + ":" + str(authority.dir_port)
		try:
			startTimeStamp = datetime.datetime.utcnow()
			startTime = time.time()
			f = urllib.urlopen(authority_address)
			for h in f.info().headers:
				if h.upper().startswith('DATE:'):
					clockskew[nickname] = datetime.datetime.strptime(h[6:].strip(), '%a, %d %b %Y %H:%M:%S %Z')
			processing = time.time() - startTime
			if processing > 5:
				clockskew[nickname] -= datetime.timedelta(seconds=(processing / 2))
			clockskew[nickname] -= startTimeStamp
			clockskew[nickname] = clockskew[nickname].total_seconds()
		except:
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
		print c, skew[c]