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

def get_dirauths_in_tables():
    return "faravahar, gabelmoo, dizum, moria1, urras, maatuska, longclaw, tor26, dannenberg, turtles, bastet".split(", ")


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
    elif key == "27102BC123E7AF1D4741AE047E160C91ADC76B21":
        return "bastet"
    else:
        raise Exception("Unexpcected dirauth key: " + key + " " + filename)

def unix_time(dt):
    return (dt - datetime.datetime.utcfromtimestamp(0)).total_seconds() * 1000.0

def ut_to_datetime(ut):
    return datetime.datetime.utcfromtimestamp(ut / 1000)

def ut_to_datetime_format(ut):
    return ut_to_datetime(ut).strftime("%Y-%m-%d-%H-%M-%S")

def get_time_from_filename(filename):
    voteTime = filename.split('-')
    if len(voteTime) < 7:
        raise Exception("Strange filename: " + filename)

    v = [int(x) for x in filename.split('-')[0:6]]
    voteTime = datetime.datetime(v[0], v[1], v[2], v[3], v[4], v[5])
    voteTime = unix_time(voteTime)
    return voteTime

def dirauth_relay_votes(directory, dirAuths, dbc):
    dirauth_columns = ""
    dirauth_columns_questions = ""
    for d in dirAuths:
        dirauth_columns += d + "_known integer, " + d + "_running integer, " + d + "_bwauth integer, "
        dirauth_columns_questions += ",?,?,?"

    dbc.execute("CREATE TABLE IF NOT EXISTS vote_data(date integer, " + dirauth_columns + "PRIMARY KEY(date ASC))")
    dbc.commit()

    votes = {}
    for root, dirs, files in os.walk(directory):
        for f in files:
            filepath = os.path.join(root, f)
            print(filepath)

            if '"' in f:
                raise Exception("Potentially malicious filename")
            elif "votes-" in f and ".tar" in f:
                continue
            elif "consensuses-" in f and ".tar" in f:
                continue
            elif "-vote-" not in f:
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
                print("Found two votes for dirauth " + dirauth + " and time " + filepath)

            votes[voteTime][dirauth]['present'] = 1
            votes[voteTime][dirauth]['known'] = int(subprocess.check_output('egrep "^r " "' + filepath + '" | wc -l', shell=True))
            votes[voteTime][dirauth]['running'] = int(subprocess.check_output('egrep "^s " "' + filepath + '" | grep " Running" | wc -l', shell=True))
            votes[voteTime][dirauth]['bwlines'] = int(subprocess.check_output('grep Measured= "' + filepath + '" | wc -l', shell=True))

    for t in votes:
        print(ut_to_datetime(t))
        print("\t", len(votes[t]))
        for d in votes[t]:
            print("\t", d, votes[t][d]['bwlines'], votes[t][d]['running'])
    
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

def bwauth_measurements(directory, dirAuths, dbc):
    #Find all the consensuses and votesrm
    votes = {}
    consensuses = {}
    for root, dirs, files in os.walk(directory):
        for f in files:
            filepath = os.path.join(root, f)

            if '"' in f:
                raise Exception("Potentially malicious filename")
            elif "votes-" in f and ".tar" in f:
                continue
            elif "consensuses-" in f and ".tar" in f:
                continue

            if "-consensus" in f:
                consensusTime = get_time_from_filename(f)
                if consensusTime not in consensuses:
                    consensuses[consensusTime] = filepath
                else:
                    print("Found two consensuses with the same time:", ut_to_datetime(consensusTime))

                #print "Consensus:", filepath
            elif "-vote-" in f:
                voteTime = get_time_from_filename(f)

                # Test to see if we already processed this one
                cur = dbc.cursor()
                cur.execute("SELECT * FROM bwauth_data WHERE date = ? AND faravahar_above IS NOT NULL", (voteTime,))
                if cur.fetchone():
                    #print("Skipping", f, "because we already processed it")
                    continue
                elif voteTime not in votes:
                    votes[voteTime] = {}

                dirauth = get_dirauth_from_filename(f)

                if dirauth not in dirAuths:
                    raise Exception("Found a dirauth I don't know about (probably spelling): " + dirauth)
                elif dirauth not in votes[voteTime]:
                    votes[voteTime][dirauth] = filepath
                else:
                    print("Found two votes for dirauth " + dirauth + ":", filepath, "and", votes[voteTime][dirauth])

                #print "Vote:", dirauth, filepath

    print("Found %s consensuses" % len(consensuses))
    print("Found %s votes" % len(votes))

    #Make sure we have a consensus for each vote
    to_del = []
    for v in votes:
        if v not in consensuses:
            print("Have votes for time", ut_to_datetime(v), "but no consensus!")
            to_del.append(v)
            #sys.exit(1)
    for i in to_del:
        del votes[i]

    #Make the table
    bwauth_columns = ""
    bwauth_columns_questions = ""
    for d in dirAuths:
        bwauth_columns += d + "_above integer, " + d + "_shared integer, " + d + "_exclusive integer, " + d + "_below integer, " + d + "_unmeasured integer, "
        bwauth_columns_questions += ",?,?,?,?,?"

    dbc.execute("CREATE TABLE IF NOT EXISTS bwauth_data(date integer, " + bwauth_columns + "PRIMARY KEY(date ASC))")
    dbc.commit()

    reviewed = 0
    for v in votes:
        reviewed += 1
        print("Reviewing", consensuses[v], "(" + str(reviewed) + "/" + str(len(votes)) + ")")

        #Get the consensus data
        consensusRouters = {}
        reader = stem.descriptor.parse_file(consensuses[v])
        for relay in reader:
            consensusRouters[relay.fingerprint] = "Unmeasured" if relay.is_unmeasured else relay.bandwidth
        
        #The vote data
        bwauthVotes = {}
        for d in votes[v]:
            if d not in bwauthVotes:
                bwauthVotes[d] = {}

            measured_something = False
            reader = stem.descriptor.parse_file(votes[v][d])
            for relay in reader:
                if relay.measured:
                    bwauthVotes[d][relay.fingerprint] = relay.measured
                    measured_something = True

            if not measured_something:
                del bwauthVotes[d]

        #Now match them up and store the data
        thisConsensusResults = {}
        for r in consensusRouters:
            for d in bwauthVotes:
                had_any_value = False
                if d not in thisConsensusResults:
                    thisConsensusResults[d] = {'unmeasured' : 0, 'above' : 0, 'below' : 0, 'exclusive' : 0 , 'shared' : 0}

                if consensusRouters[r] == "Unmeasured":
                    continue
                elif r not in bwauthVotes[d]:
                    had_any_value = True
                    thisConsensusResults[d]['unmeasured'] += 1
                elif consensusRouters[r] < bwauthVotes[d][r]:
                    had_any_value = True
                    thisConsensusResults[d]['above'] += 1
                elif consensusRouters[r] > bwauthVotes[d][r]:
                    had_any_value = True
                    thisConsensusResults[d]['below'] += 1
                elif consensusRouters[r] == bwauthVotes[d][r] and \
                    1 == len([1 for d_i in bwauthVotes if d_i in bwauthVotes and r in bwauthVotes[d_i] and bwauthVotes[d_i][r] == consensusRouters[r]]):
                    had_any_value = True
                    thisConsensusResults[d]['exclusive'] += 1
                elif consensusRouters[r] == bwauthVotes[d][r] and \
                    1 != len([1 for d_i in bwauthVotes if d_i in bwauthVotes and r in bwauthVotes[d_i] and bwauthVotes[d_i][r] == consensusRouters[r] ]):
                    had_any_value = True
                    thisConsensusResults[d]['shared'] += 1
                else:
                    print("What case am I in???")
                    sys.exit(1)

                if not had_any_value:
                    del thisConsensusResults[d]

        insertValues = [v]
        for d in dirAuths: 
            if d in thisConsensusResults:
                insertValues.append(thisConsensusResults[d]['above'])
                insertValues.append(thisConsensusResults[d]['shared'])
                insertValues.append(thisConsensusResults[d]['exclusive'])
                insertValues.append(thisConsensusResults[d]['below'])
                insertValues.append(thisConsensusResults[d]['unmeasured'])
            else:
                insertValues.append(None)
                insertValues.append(None)
                insertValues.append(None)
                insertValues.append(None)
                insertValues.append(None)
         
        dbc.execute("INSERT OR REPLACE INTO bwauth_data VALUES (?" + bwauth_columns_questions + ")", insertValues)
        dbc.commit()
        
def my_listener(path, exception):
    print("Skipped!")
    print(path)
    print(exception)


def main(itype, directory):
    dirAuths = get_dirauths_in_tables()
    dbc = sqlite3.connect(os.path.join('data', 'historical.db'))

    if itype == "dirauth_relay_votes":
        dirauth_relay_votes(directory, dirAuths, dbc)
    elif itype == "bwauth_measurements":
        bwauth_measurements(directory, dirAuths, dbc)
    else:
        print("Unknown ingestion type")

if __name__ == '__main__':
    try:
        if len(sys.argv) != 3:
            print("Usage: ", sys.argv[0], "ingestion-type vote-directory")
        else:
            main(sys.argv[1], sys.argv[2])
    except:
        msg = "%s failed with:\n\n%s" % (sys.argv[0], traceback.format_exc())
        print("Error: %s" % msg)

