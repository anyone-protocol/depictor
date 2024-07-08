#!/usr/bin/env python3
# Copyright 2013, Damian Johnson, Tom Ritter, and The Tor Project
# See LICENSE for licensing information

"""
Performs a variety of checks against the present votes and consensus.
"""

import os
import sys
import time
import shutil
import sqlite3
import datetime
import operator
import traceback

import stem.descriptor
import stem.descriptor.remote
import stem.util.conf
import stem.util.enum

from stem.directory import Fallback
from stem.directory import Authority

from utility import *
from website import WebsiteWriter
from graphs import GraphWriter


#If you're running your own test network, you define your DirAuths here
# dir-source line: dir-source authority_name v3ident hostname ip  DirPort  OrPort
# r line: r nickname base64(fingerprint + "=")   -> python -c "x = ''; import sys; import base64; sys.stdout.write(''.join('{:02x}'.format(ord(c)) for c in base64.b64decode(x)))"

#Also make sure to define the list of bwauths in the consensus.cfg file

stem.directory.DIRECTORY_AUTHORITIES = {
'ATORDAeuclive': Authority(
   nickname = 'ATORDAeuclive',
   address = '49.13.145.234',
   or_port = 9201,
   dir_port = 9230,
   fingerprint = '9F01AEC951F037664F8762D54E0EEA8E6809176A',
   v3ident = '9425F567C631319350C6EEF65E775A8AC0699DA0',
 ),
'ATORDAuselive': Authority(
   nickname = 'ATORDAuselive',
   address = '5.161.108.187',
   or_port = 9201,
   dir_port = 9230,
   fingerprint = '54849A361F8CED0D1B70B722CB8B33E9071E5561',
   v3ident = '6F3E34A99853CC3CB2D9E7A6FF8D64ED75C8B9E8',
 ),
'ATORDAuswlive': Authority(
   nickname = 'ATORDAuswlive',
   address = '5.78.90.106',
   or_port = 9201,
   dir_port = 9230,
   fingerprint = '2E397C3F4BC12B4F92940C2B92D4E091E82D2D31',
   v3ident = 'C30FBEF011CDFDDD3879BF2BA77A56274899B1BB',
 ),
'AnyoneAshLive': Authority(
   nickname = 'AnyoneAshLive',
   address = '5.161.228.187',
   or_port = 9201,
   dir_port = 9230,
   fingerprint = 'F3FE23A099FB8BBD36AD4B86CB32B573AB790234',
   v3ident = '6CE85CF74AB78E4D350E0418234B97F47AB32A20',
 ),
'AnyoneHilLive': Authority(
   nickname = 'AnyoneHilLive',
   address = '5.78.94.15',
   or_port = 9201,
   dir_port = 9230,
   fingerprint = '5F94833043EB92018319CB83559706CC1127151B',
   v3ident = '39C78145CFDF464E624626D4F78A315387132082',
 ),
'AnyoneHelLive': Authority(
   nickname = 'AnyoneHelLive',
   address = '95.216.32.105',
   or_port = 9201,
   dir_port = 9230,
   fingerprint = '9EDC92CC9C7C59E3FD871BC7F1ACD0885FD6CBF7',
   v3ident = '5F18C895685A4207E0778FEB2A9CE4C90DABE7A6',
 ),
'AnyoneFalLive': Authority(
   nickname = 'AnyoneFalLive',
   address = '176.9.29.53',
   or_port = 9201,
   dir_port = 9230,
   fingerprint = '5F18C895685A4207E0778FEB2A9CE4C90DABE7A6',
   v3ident = '271F7D1592BF37AEB67BF48164928720EF9D0648',
 ),
}

CONFIG = stem.util.conf.config_dict('consensus', {
	'bwauths': [],
	'ignore_fallback_authorities' : False,
	'graph_logical_min' : 125,
	'graph_logical_max' : 25000,
	'clockskew_threshold': 0,
})

def main():
	print('Loading configuration data')
	config = stem.util.conf.get_config("consensus")
	config.load(os.path.join(os.path.dirname(__file__), 'data', 'consensus.cfg'))
	set_config(CONFIG)

	print('Fetching votes')
	validation = validate_votes()
	consensuses, consensus_fetching_issues, consensus_fetching_runtimes = get_consensuses()
	votes, vote_fetching_issues, vote_fetching_runtimes = get_votes()
	clockskew = get_clockskew()

	print('Updating download statistics file')
	f = open(os.path.join(os.path.dirname(__file__), 'out', 'download-stats.csv'), 'a')
	for ds in consensus_fetching_runtimes:
		f.write("%s,%i,%i\n" % (ds, time.time() * 1000, int(consensus_fetching_runtimes[ds] * 1000)))
	f.close()

	fallback_dirs = []

	# great for debugging
	import pickle
	pickle.dump(consensuses, open('consensus.p', 'wb'))
	pickle.dump(votes, open('votes.p', 'wb'))
	pickle.dump(fallback_dirs, open('fallback_dirs.p', 'wb'))
	pickle.dump(validation, open('validation.p', 'wb'))

	dbc = sqlite3.connect(os.path.join('data', 'historical.db'))

	# Create database placeholders
	for tbl in ["bwauth_data"]:
		tbl_exists = dbc.execute("SELECT name FROM sqlite_master WHERE type = 'table' and name = ?", (tbl,))
		if tbl_exists.fetchone():
			date_rows = dbc.execute("SELECT date from " + tbl + " ORDER BY date ASC")
			previous = 0
			for d in date_rows.fetchall():
				d = d[0]
				if previous == 0:
					pass
				else:
					expected_0 = ut_to_datetime(previous) + datetime.timedelta(hours=1)
					expected_1 = ut_to_datetime(previous) + datetime.timedelta(minutes=30)
					if ut_to_datetime(d) in [expected_0, expected_1]:
						pass
					else:
						print("We seem to be missing", consensus_datetime_format(expected_1))
						dbc.execute("INSERT OR REPLACE INTO " + tbl + "(date) VALUES (?)", (unix_time(expected_1),))
						dbc.commit()
				previous = d

	# Calculate the number of known and measured relays for each dirauth and insert it into the database
	data = {}
	for dirauth_nickname in votes:
		vote = votes[dirauth_nickname]

		runningRelays    = 0
		bandwidthWeights = 0
		for r in vote.routers.values():
			if r.measured and r.measured >= int(0):
				bandwidthWeights += 1
			if u'Running' in r.flags:
				runningRelays += 1
		data[dirauth_nickname] = {'known' : len(vote.routers.values()), 'running' : runningRelays, 'bwlines' : bandwidthWeights}

	vote_data_columns = set()
	vote_data_schema = dbc.execute("PRAGMA table_info(vote_data)")
	for c in vote_data_schema:
		vote_data_columns.add(c[1].replace("_known", "").replace("_running", "").replace("_bwauth", "").lower())

	insertValues = [unix_time(list(consensuses.values())[0].valid_after)]
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

	#Calculate the bwauth statistics and insert it into the database
	data = {}
	for dirauth_nickname in votes:
		vote = votes[dirauth_nickname]
		data[dirauth_nickname] = {'unmeasured' : 0, 'above' : 0, 'below' : 0, 'exclusive' : 0 , 'shared' : 0}

		had_any_value = False
		for r in list(consensuses.values())[0].routers.values():
			if r.is_unmeasured:
				continue
			elif r.fingerprint not in vote.routers or vote.routers[r.fingerprint].measured == None:
				data[dirauth_nickname]['unmeasured'] += 1
			elif r.bandwidth < vote.routers[r.fingerprint].measured:
				had_any_value = True
				data[dirauth_nickname]['above'] += 1
			elif r.bandwidth > vote.routers[r.fingerprint].measured:
				had_any_value = True
				data[dirauth_nickname]['below'] += 1
			elif r.bandwidth == vote.routers[r.fingerprint].measured and \
				 1 == len([1 for d_i in votes if r.fingerprint in votes[d_i].routers and votes[d_i].routers[r.fingerprint].measured == r.bandwidth]):
				had_any_value = True
				data[dirauth_nickname]['exclusive'] += 1
			elif r.bandwidth == vote.routers[r.fingerprint].measured and \
				 1 != len([1 for d_i in votes if r.fingerprint in votes[d_i].routers and votes[d_i].routers[r.fingerprint].measured == r.bandwidth]):
				had_any_value = True
				data[dirauth_nickname]['shared'] += 1
			else:
				print("What case am I in???")
				sys.exit(1)

		if not had_any_value:
			del data[dirauth_nickname]

	bwauth_stats_data_columns = set()
	bwauth_stats_data_schema = dbc.execute("PRAGMA table_info(bwauth_data)")
	for c in bwauth_stats_data_schema:
		bwauth_stats_data_columns.add(c[1].replace("_above", "").replace("_shared", "").replace("_exclusive", "").replace("_below", "").replace("_unmeasured", "").lower())

	insertValues = [unix_time(list(consensuses.values())[0].valid_after)]
	createColumns = ""
	insertColumns = "date"
	insertQuestions = ""
	for dirauth_nickname in get_dirauths():
		if bwauth_stats_data_columns and dirauth_nickname not in bwauth_stats_data_columns:
			dbc.execute("ALTER TABLE bwauth_data ADD COLUMN " + dirauth_nickname + "_above integer")
			dbc.execute("ALTER TABLE bwauth_data ADD COLUMN " + dirauth_nickname + "_shared integer")
			dbc.execute("ALTER TABLE bwauth_data ADD COLUMN " + dirauth_nickname + "_exclusive integer")
			dbc.execute("ALTER TABLE bwauth_data ADD COLUMN " + dirauth_nickname + "_below integer")
			dbc.execute("ALTER TABLE bwauth_data ADD COLUMN " + dirauth_nickname + "_unmeasured integer")
			dbc.commit()
		createColumns += dirauth_nickname + "_above integer, " + dirauth_nickname + "_shared integer, " + dirauth_nickname + "_exclusive integer, " + dirauth_nickname + "_below integer, " + dirauth_nickname + "_unmeasured integer, "

		if dirauth_nickname in votes and dirauth_nickname in data:
			insertColumns += ", " + dirauth_nickname + "_above, " + dirauth_nickname + "_shared, " + dirauth_nickname + "_exclusive, " + dirauth_nickname + "_below, " + dirauth_nickname + "_unmeasured "
			insertQuestions += ",?,?,?,?,?"
			insertValues.append(data[dirauth_nickname]['above'])
			insertValues.append(data[dirauth_nickname]['shared'])
			insertValues.append(data[dirauth_nickname]['exclusive'])
			insertValues.append(data[dirauth_nickname]['below'])
			insertValues.append(data[dirauth_nickname]['unmeasured'])

	if not bwauth_stats_data_columns:
		dbc.execute("CREATE TABLE IF NOT EXISTS bwauth_data(date integer, " + createColumns + " PRIMARY KEY(date ASC));")
		dbc.commit()

	dbc.execute("INSERT OR REPLACE INTO bwauth_data(" + insertColumns + ") VALUES (?" + insertQuestions + ")", insertValues)
	dbc.commit()

	# Write out the bwauth csv file
	bwauth_data_columns = []
	bwauth_data_schema = dbc.execute("PRAGMA table_info(bwauth_data)")
	for c in bwauth_data_schema:
		bwauth_data_columns.append(c[1])

	bwauth_data = dbc.execute("SELECT * from bwauth_data ORDER BY date DESC LIMIT 2160")
	f = open(os.path.join(os.path.dirname(__file__), 'out', 'bwauth-stats.csv'), 'w')
	for c in bwauth_data_columns:
		f.write(c + ",")
	f.write("\n")
	for r in bwauth_data.fetchall():
		for v in r:
			f.write(("0" if v == None else str(v)) + ",")
		f.write("\n")
	f.close()

	bwauth_data = dbc.execute("SELECT * from bwauth_data ORDER BY date DESC")
	f = open(os.path.join(os.path.dirname(__file__), 'out', 'bwauth-stats-all.csv'), 'w')
	for c in bwauth_data_columns:
		f.write(c + ",")
	f.write("\n")
	for r in bwauth_data.fetchall():
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
	w.set_clockskew(clockskew)
	w.set_validation(validation)
	w.write_website(os.path.join(os.path.dirname(__file__), 'out', 'consensus-health.html'), \
		True, os.path.join(os.path.dirname(__file__), 'out', 'relay-indexes.txt'))
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

	del consensuses, votes
	time.sleep(1)
	archived = os.path.join(os.path.dirname(__file__), 'out', \
				'consensus-health-' + consensus_time.strftime("%Y-%m-%d-%H-%M") + '.html')
	shutil.copyfile(os.path.join(os.path.dirname(__file__), 'out', 'consensus-health.html'), archived)
	shutil.copyfile(os.path.join('data', 'historical.db'), os.path.join('out', 'historical.db'))

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
		print("Error: %s" % msg)
