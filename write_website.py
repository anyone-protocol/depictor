#!/usr/bin/env python
# Copyright 2013, Damian Johnson, Tom Ritter, and The Tor Project
# See LICENSE for licensing information

"""
Performs a variety of checks against the present votes and consensus.
"""

import os
import sys
import time
import datetime
import operator
import traceback
import subprocess

import stem.descriptor
import stem.descriptor.remote
import stem.util.conf
import stem.util.enum

from stem import Flag
from stem.util.lru_cache import lru_cache

from website import WebsiteWriter
from graphs import GraphWriter

DIRECTORY_AUTHORITIES = stem.descriptor.remote.get_authorities()

CONFIG = stem.util.conf.config_dict('consensus', {
	'ignored_authorities': [],
	'bandwidth_authorities': [],
	'known_params': [],
})

downloader = stem.descriptor.remote.DescriptorDownloader(
	timeout = 60,
	fall_back_to_authority = False,
	document_handler = stem.descriptor.DocumentHandler.DOCUMENT,
)


@lru_cache()
def directory_authorities():
	return dict((k, v) for (k, v) in DIRECTORY_AUTHORITIES.items() if k not in CONFIG['ignored_authorities'])


def main():
	# loads configuration data
	config = stem.util.conf.get_config("consensus")
	config.load(os.path.join(os.path.dirname(__file__), 'data', 'consensus.cfg'))

	consensuses, consensus_fetching_issues, consensus_fetching_runtimes = get_consensuses()
	votes, vote_fetching_issues, vote_fetching_runtimes = get_votes()

	# updates the download statistics file
	f = open(os.path.join(os.path.dirname(__file__), 'out', 'download-stats.csv'), 'a')
	for ds in consensus_fetching_runtimes:
		f.write("%s,%i,%i\n" % (ds, time.time() * 1000, int(consensus_fetching_runtimes[ds] * 1000)))
	f.close()

	# great for debugging
	#import pickle
	#pickle.dump(consensuses, open('consensus.p', 'wb'))
	#pickle.dump(votes, open('votes.p', 'wb'))

	# produces the website
	w = WebsiteWriter()
	w.set_consensuses(consensuses)
	w.set_votes(votes)
	w.set_config(CONFIG)
	w.write_website(os.path.join(os.path.dirname(__file__), 'out', 'consensus-health.html'), True)
	w.write_website(os.path.join(os.path.dirname(__file__), 'out', 'index.html'), False)

	consensus_time = w.get_consensus_time()
	del w

	# produces the website
	g = GraphWriter()
	g.set_consensuses(consensuses)
	g.set_votes(votes)
	g.set_config(CONFIG)
	g.write_website(os.path.join(os.path.dirname(__file__), 'out', 'graphs.html'))

	del g

	# delete giant data structures for subprocess forking by piling hacks on top of each other
	import gc
	del consensuses, votes
	gc.collect()
	time.sleep(1)
	archived = os.path.join(os.path.dirname(__file__), 'out', \
				'consensus-health-' + consensus_time.strftime("%Y-%m-%d-%H-%M") + '.html')
	subprocess.call(["cp", os.path.join(os.path.dirname(__file__), 'out', 'consensus-health.html'), archived])
	#Do not gzip anymore, as Apache is not configured for it.
	#subprocess.call(["gzip", "-9", archived])
	#subprocess.call(["ln", "-s", archived + ".gz", archived])

	# remove old files
	weeks_to_keep = 3
	files = [f for f in os.listdir(os.path.join(os.path.dirname(__file__), 'out'))]
	for f in files:
		if f.startswith("consensus-health-"):
			f_time = f.replace("consensus-health-", "").replace(".html", "").replace(".gz", "")
			f_time = datetime.datetime.strptime(f_time, "%Y-%m-%d-%H-%M")
			if (consensus_time - f_time).days > weeks_to_keep * 7:
				os.remove(os.path.join(os.path.dirname(__file__), 'out', f))


def get_consensuses():
	"""
	Provides a mapping of directory authority nicknames to their present consensus.

	:returns: tuple of the form ({authority => consensus}, issues, runtimes)
	"""

	return _get_documents('consensus', '/tor/status-vote/current/consensus')


def get_votes():
	"""
	Provides a mapping of directory authority nicknames to their present vote.

	:returns: tuple of the form ({authority => vote}, issues, runtimes)
	"""

	return _get_documents('vote', '/tor/status-vote/current/authority')


def _get_documents(label, resource):
	documents, issues, runtimes = {}, [], {}

	for authority in directory_authorities().values():
		if authority.v3ident is None:
			continue	# not a voting authority

		query = downloader.query(
			resource,
			endpoints = [(authority.address, authority.dir_port)],
			default_params = False,
		)

		try:
			start_time = time.time()
			documents[authority.nickname] = query.run()[0]
			runtimes[authority.nickname] = time.time() - start_time
		except Exception, exc:
			if label == 'vote':
				# try to download the vote via the other authorities

				v3ident = directory_authorities()[authority.nickname].v3ident

				query = downloader.query(
					'/tor/status-vote/current/%s' % v3ident,
					default_params = False,
				)

				query.run(True)

				if not query.error:
					documents[authority.nickname] = list(query)[0]
					continue

			issues.append(('AUTHORITY_UNAVAILABLE', label, authority, query.download_url, exc))

	return documents, issues, runtimes


if __name__ == '__main__':
	try:
		main()
	except:
		msg = "%s failed with:\n\n%s" % (sys.argv[0], traceback.format_exc())
		print "Error: %s" % msg
