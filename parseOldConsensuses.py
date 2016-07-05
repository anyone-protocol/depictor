#!/usr/bin/env python
# Copyright 2013, Damian Johnson, Tom Ritter, and The Tor Project
# See LICENSE for licensing information


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

from stem import Flag
from stem.util.lru_cache import lru_cache

def get_dirauths_in_tables():
	return "faravahar, gabelmoo, dizum, moria1, urras, maatuska, longclaw, tor26, dannenberg, turtles".split(", ")


def get_dirauth_from_filename(filename):
	key = filename.split('-')
	if len(key) < 9:
		raise Exception("Strange filename: " + filename)

	key = key[-2]
	if key == "EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97":
		return "faravahar"
	elif key == "ED03BB616EB2F60BEC80151114BB25CEF515B226":
		return "gabelmoo"
	elif key == "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58":
		return "dizum"
	elif key == "D586D18309DED4CD6D57C18FDB97EFA96D330566":
		return "moria1"
	elif key == "80550987E1D626E3EBA5E5E75A458DE0626D088C":
		return "urras"
	elif key == "49015F787433103580E3B66A1707A00E60F2D15B":
		return "maatuska"
	elif key == "23D15D965BC35114467363C165C4F724B64B4F66":
		return "longclaw"
	elif key == "14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4":
		return "tor26"
	elif key == "0232AF901C31A04EE9848595AF9BB7620D4C5B2E" or key == "585769C78764D58426B8B52B6651A5A71137189A":
		return "dannenberg"
        elif key == "27B6B5996C426270A5C95488AA5BCEB6BCC86956":
                return "turtles"
	else:
		raise Exception("Unexpcected dirauth key: " + key + " " + filename)

def unix_time(dt):
    return (dt - datetime.datetime.utcfromtimestamp(0)).total_seconds() * 1000.0

def get_time_from_filename(filename):
	voteTime = filename.split('-')
	if len(voteTime) < 9:
		raise Exception("Strange filename: " + filename)

	v = [int(x) for x in filename.split('-')[0:6]]
	voteTime = datetime.datetime(v[0], v[1], v[2], v[3], v[4], v[5])
	voteTime = unix_time(voteTime)
	return voteTime

def main(dir):
	dirAuths = get_dirauths_in_tables()
	dbc = sqlite3.connect(os.path.join('data', 'historical.db'))

	dirauth_columns = ""
	dirauth_columns_questions = ""
	for d in dirAuths:
		dirauth_columns += d + "_known integer, " + d + "_running integer, " + d + "_bwauth integer, "
		dirauth_columns_questions += ",?,?,?"

	votes = {}
	for root, dirs, files in os.walk(dir):
		for f in files:
                        filepath = os.path.join(root, f)
                        print filepath

			if '"' in f:
				raise Exception("Potentially malicious filename")
                        elif "votes-" in f and ".tar" in f:
                                continue

			voteTime = get_time_from_filename(f)
			if voteTime not in votes:
				votes[voteTime] = {}

			dirauth = get_dirauth_from_filename(f)
			if dirauth not in dirAuths:
				raise Exception("Found a dirauth I don't know about (probably spelling): " + dirauth)
			elif dirauth not in votes[voteTime]:
				votes[voteTime][dirauth] = {}
			else:
				print "Found two votes for dirauth " + dirauth + " and time " + filepath

			votes[voteTime][dirauth]['present'] = 1
			votes[voteTime][dirauth]['known'] = int(subprocess.check_output('egrep "^r " "' + filepath + '" | wc -l', shell=True))
			votes[voteTime][dirauth]['running'] = int(subprocess.check_output('egrep "^s " "' + filepath + '" | grep " Running" | wc -l', shell=True))
			votes[voteTime][dirauth]['bwlines'] = int(subprocess.check_output('grep Measured= "' + filepath + '" | wc -l', shell=True))

	dbc.execute("CREATE TABLE IF NOT EXISTS vote_data(date integer, " + dirauth_columns + "PRIMARY KEY(date ASC))")
	dbc.commit()

	for t in votes:
		print t
		print "\t", len(votes[t])
		for d in votes[t]:
			print "\t", d, votes[t][d]['bwlines'], votes[t][d]['running']
	
		insertValues = [t]
		for d in dirAuths:
			if d in votes[t]:
				insertValues.append(votes[t][d]['known'])
				insertValues.append(votes[t][d]['running'])
				insertValues.append(votes[t][d]['bwlines'])
			else:
				insertValues.append(None)
				insertValues.append(None)
				insertValues.append(None)

		dbc.execute("INSERT OR REPLACE INTO vote_data VALUES (?" + dirauth_columns_questions + ")", insertValues)
		dbc.commit()


if __name__ == '__main__':
	try:
		if len(sys.argv) != 2:
			print "Usage: ", sys.argv[0], "vote-directory"
		else:
			main(sys.argv[1])
	except:
		msg = "%s failed with:\n\n%s" % (sys.argv[0], traceback.format_exc())
		print "Error: %s" % msg

