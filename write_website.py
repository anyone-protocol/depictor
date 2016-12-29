#!/usr/bin/env python
# Copyright 2013, Damian Johnson, Tom Ritter, and The Tor Project
# See LICENSE for licensing information

"""
Performs a variety of checks against the present votes and consensus.
"""

import os
import sys
import time
import sqlite3
import datetime
import operator
import traceback
import subprocess

import stem.descriptor
import stem.descriptor.remote
import stem.util.conf
import stem.util.enum

from stem.descriptor.remote import FallbackDirectory
from stem.descriptor.remote import DirectoryAuthority

from utility import *
from website import WebsiteWriter
from graphs import GraphWriter


#If you're running your own test network, you define your DirAuths here
# dir-source line: dir-source authority_name v3ident hostname ip  DirPort  OrPort
# r line: r nickname base64(fingerprint + "=")   -> python -c "x = ''; import sys; import base64; sys.stdout.write(''.join('{:02x}'.format(ord(c)) for c in base64.b64decode(x)))"

#stem.descriptor.remote.DIRECTORY_AUTHORITIES = {
#'Faravahar': DirectoryAuthority(
#    nickname = 'Faravahar',
#    address = '154.35.175.225',
#    or_port = 443,
#    dir_port = 80,
#    is_bandwidth_authority = True,
#    fingerprint = 'CF6D0AAFB385BE71B8E111FC5CFF4B47923733BC',
#    v3ident = 'EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97',
#  ),	
#}

CONFIG = stem.util.conf.config_dict('consensus', {
	'known_params': [],
	'ignore_fallback_authorities' : False,
	'graph_logical_min' : 125,
	'graph_logical_max' : 25000
})

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

	# Calculate the fallback directory info
	if not CONFIG['ignore_fallback_authorities']:
		fallback_dirs = stem.descriptor.remote.FallbackDirectory.from_remote()
	else:
		fallback_dirs = []
	
	# great for debugging
	#import pickle
	#pickle.dump(consensuses, open('consensus.p', 'wb'))
	#pickle.dump(votes, open('votes.p', 'wb'))
	#pickle.dump(fallback_dirs, open('fallback_dirs.p', 'wb'))


	dbc = sqlite3.connect(os.path.join('data', 'historical.db'))

	# Calculate the number of fallback directory authorities present in the consensus and insert it into the database
	if not CONFIG['ignore_fallback_authorities']:
		fallback_dirs_running = 0
		fallback_dirs_notrunning = 0
		for relay_fp in consensuses.values()[0].routers:
			if relay_fp in fallback_dirs and 'Running' in consensuses.values()[0].routers[relay_fp].flags:
				fallback_dirs_running += 1
			elif relay_fp in fallback_dirs:
				fallback_dirs_notrunning += 1
					
		insertValues = [unix_time(consensuses.values()[0].valid_after)]
		insertValues.append(fallback_dirs_running)
		insertValues.append(fallback_dirs_notrunning)
		insertValues.append(len(fallback_dirs) - fallback_dirs_running - fallback_dirs_notrunning)

		dbc.execute("CREATE TABLE IF NOT EXISTS fallback_dir_data (date integer, fallback_dirs_running integer, fallback_dirs_notrunning integer, fallback_dirs_missing integer, PRIMARY KEY(date ASC));")
		dbc.commit()

		dbc.execute("INSERT OR REPLACE INTO fallback_dir_data VALUES (?,?,?,?)", insertValues)
		dbc.commit()

		# Write out the updated csv file for the graphs
		fallback_dir_data = dbc.execute("SELECT * from fallback_dir_data ORDER BY date DESC LIMIT 2160")
		f = open(os.path.join(os.path.dirname(__file__), 'out', 'fallback-dir-stats.csv'), 'w')
		f.write("date")
		f.write(",fallback_dirs_running")
		f.write(",fallback_dirs_notrunning")
		f.write(",fallback_dirs_missing")
		f.write("\n")
		for r in fallback_dir_data.fetchall():
			for v in r:
				f.write(("0" if v == None else str(v)) + ",")
			f.write("\n")
		f.close()

	# Calculate the number of known and measured relays for each dirauth and insert it into the database
	data = {}
	for dirauth_nickname in votes:
		vote = votes[dirauth_nickname]
				
		runningRelays    = 0
		bandwidthWeights = 0
		for r in vote.routers.values():
			if r.measured >= 0L:
				bandwidthWeights += 1
			if u'Running' in r.flags:
				runningRelays += 1
		data[dirauth_nickname] = {'known' : len(vote.routers.values()), 'running' : runningRelays, 'bwlines' : bandwidthWeights}

	vote_data_columns = set()
	vote_data_schema = dbc.execute("PRAGMA table_info(vote_data)")
	for c in vote_data_schema:
		vote_data_columns.add(c[1].replace("_known", "").replace("_running", "").replace("_bwauth", "").lower())

	insertValues = [unix_time(consensuses.values()[0].valid_after)]
	createColumns = ""
	insertColumns = "date"
	insertQuestions = ""

	for dirauth_nickname in get_dirauths():
		if vote_data_columns and dirauth_nickname not in vote_data_columns:
			dbc.execute("ALTER TABLE vote_data ADD COLUMN " + dirauth_nickname + "_known integer")
			dbc.execute("ALTER TABLE vote_data ADD COLUMN " + dirauth_nickname + "_running integer")
			dbc.execute("ALTER TABLE vote_data ADD COLUMN " + dirauth_nickname + "_bwauth integer")
			dbc.commit()
		createColumns += dirauth_nickname + "_known integer, " + dirauth_nickname + "_running integer, " + dirauth_nickname + "_bwauth integer, "
		if dirauth_nickname in votes:
			insertColumns += ", " + dirauth_nickname + "_known" + ", " + dirauth_nickname + "_running" + ", " + dirauth_nickname + "_bwauth"
			insertQuestions += ",?,?,?"
			insertValues.append(data[dirauth_nickname]['known'])
			insertValues.append(data[dirauth_nickname]['running'])
			insertValues.append(data[dirauth_nickname]['bwlines'])

	if not vote_data_columns:
		dbc.execute("CREATE TABLE IF NOT EXISTS vote_data(date integer, " + createColumns + " PRIMARY KEY(date ASC));")
		dbc.commit()

	dbc.execute("INSERT OR REPLACE INTO vote_data(" + insertColumns + ") VALUES (?" + insertQuestions + ")", insertValues)
	dbc.commit()

	# Write out the updated csv file for the graphs
	vote_data_columns = []
	vote_data_schema = dbc.execute("PRAGMA table_info(vote_data)")
	for c in vote_data_schema:
		vote_data_columns.append(c[1])

	vote_data = dbc.execute("SELECT * from vote_data ORDER BY date DESC LIMIT 2160")
	f = open(os.path.join(os.path.dirname(__file__), 'out', 'vote-stats.csv'), 'w')
	for c in vote_data_columns:
		f.write(c + ",")
	f.write("\n")
	for r in vote_data.fetchall():
		for v in r:
			f.write(("0" if v == None else str(v)) + ",")
		f.write("\n")
	f.close()

	# produces the website
	w = WebsiteWriter()
	w.set_config(CONFIG)
	w.set_consensuses(consensuses)
	w.set_votes(votes)
	w.set_fallback_dirs(fallback_dirs)
	w.write_website(os.path.join(os.path.dirname(__file__), 'out', 'consensus-health.html'), True)
	w.write_website(os.path.join(os.path.dirname(__file__), 'out', 'index.html'), False)

	consensus_time = w.get_consensus_time()
	del w

	# produces the website
	g = GraphWriter()
	g.set_config(CONFIG)
	g.set_consensuses(consensuses)
	g.set_votes(votes)
	g.set_fallback_dirs(fallback_dirs)
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

	subprocess.call(["cp", os.path.join('data', 'historical.db'), os.path.join('out', 'historical.db')])

	# remove old files
	weeks_to_keep = 3
	files = [f for f in os.listdir(os.path.join(os.path.dirname(__file__), 'out'))]
	for f in files:
		if f.startswith("consensus-health-"):
			f_time = f.replace("consensus-health-", "").replace(".html", "").replace(".gz", "")
			f_time = datetime.datetime.strptime(f_time, "%Y-%m-%d-%H-%M")
			if (consensus_time - f_time).days > weeks_to_keep * 7:
				os.remove(os.path.join(os.path.dirname(__file__), 'out', f))


if __name__ == '__main__':
	try:
		main()
	except:
		msg = "%s failed with:\n\n%s" % (sys.argv[0], traceback.format_exc())
		print "Error: %s" % msg
