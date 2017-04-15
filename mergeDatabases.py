#!/usr/bin/env python

import os
import sys
import time
import sqlite3
import datetime
import operator
import traceback
import subprocess

if __name__ == '__main__':
	if len(sys.argv) != 3:
		print "Usage: ", sys.argv[0], "src.db dest.db"
		print "\tMerge all the data from src into dest"
		sys.exit(1)

	if not os.path.isfile(sys.argv[1]):
		print "Source is not a file"
		sys.exit(1)
	if not os.path.isfile(sys.argv[2]):
		print "Dest is not a file"
		sys.exit(1)

	src = sqlite3.connect(sys.argv[1])
	dst = sqlite3.connect(sys.argv[2])

	s_tbls = src.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
	for t in s_tbls:
		t = t[0]
		skip_table = False

		d_tbl = dst.execute("SELECT name FROM sqlite_master WHERE type = 'table' and name = ?", (t,))
		if not d_tbl.fetchone():
			print "Skipping table", t, "which is in src but not in dst"
			continue

		s_cols = src.execute("PRAGMA table_info(" + t + ")")
		d_cols = dst.execute("PRAGMA table_info(" + t + ")")
		s_cols = s_cols.fetchall()
		d_cols = d_cols.fetchall()
		if len(s_cols) != len(d_cols):
			print "Skipping table", t, "which has", len(s_cols), "columns in src and", len(d_cols)
			continue
		for i in range(len(s_cols)):
			if s_cols[i] != d_cols[i]:
				print "Skipping table", t, "because column", 1, "is", s_cols[i], "in src and", d_cols[i], "in dst"
				skip_table = True
		
		if skip_table:
			continue

		print "Merging table", t
		merged = 0
		s = src.execute("SELECT * FROM " + t)
		for r in s.fetchall():
			date = r[0]
			has_value = False
			for v in r[1:]:
				if v:
					has_value = True
			if has_value:
				merged += 1
				dst.execute("INSERT OR REPLACE INTO " + t + " VALUES (" + ",".join("?" * len(r)) + ")", r)
				dst.commit()
		print "Inserted or updated", merged, "rows"