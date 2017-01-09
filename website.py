#!/usr/bin/env python
# See LICENSE for licensing information

"""
Produces an HTML file for easily viewing voting and consensus differences
Ported from Java version Doctor
"""

import os
import time
import operator
import datetime

from base64 import b64decode
from Crypto.PublicKey import RSA

import stem.descriptor.remote

from utility import get_dirauths, get_bwauths

class WebsiteWriter:
	consensus = None
	votes = None
	fallback_dirs = None
	known_authorities = []
	bandwidth_authorities = []
	consensus_expiry = datetime.timedelta(hours=3)
	directory_key_warning_time = datetime.timedelta(days=14)
	config = {}
	known_params = []
	def write_website(self, filename, include_relay_info=True):
		self.site = open(filename, 'w')
		self._write_page_header(include_relay_info)
		self._write_valid_after_time()
		self._write_signatures()
		self._write_known_flags()
		self._write_flag_thresholds()
		self._write_number_of_relays_voted_about(True)
		self._write_consensus_methods()
		self._write_recommended_versions()
		self._write_consensus_parameters()
		self._write_authority_keys()
		self._write_shared_random()
		self._write_protocols()
		self._write_bandwidth_scanner_status(True)
		self._write_fallback_directory_status(True)
		self._write_authority_versions()
		self._write_download_statistics()
		self._write_relay_info_summary()
		if include_relay_info:
			self._write_relay_info_table()
		else:
			self._write_relay_info_pointer()
		self._write_page_footer()
		self.site.close()

	def set_consensuses(self, c):
		self.consensuses = c
		self.consensus = max(c.itervalues(), key=operator.attrgetter('valid_after'))
		self.known_authorities = get_dirauths().keys()
		self.bandwidth_authorities = get_bwauths().keys()
	def set_votes(self, v):
		self.votes = v
	def set_consensus_expiry(self, timedelta):
		self.consensus_expiry = timedelta
	def set_directory_key_warning_time(self, timedelta):
		self.directory_key_warning_time = timedelta
	def set_config(self, config):
		self.config = config
		self.known_params = config['known_params']
	def set_fallback_dirs(self, fallback_dirs):
		self.fallback_dirs = fallback_dirs
	def get_consensus_time(self):
		return self.consensus.valid_after

	#-----------------------------------------------------------------------------------------
	def _write_page_header(self, include_relay_info):
		"""
		Write the HTML page header including the metrics website navigation.
		"""
		self.site.write("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 "
			+ "Transitional//EN\">\n"
			+ "<html>\n"
			+ "  <head>\n"
			+ "    <title>Consensus health</title>\n"
			+ "    <meta http-equiv=\"content-type\" content=\"text/html; charset=ISO-8859-1\">\n"
			+ "    <link href=\"stylesheet-ltr.css\" type=\"text/css\" rel=\"stylesheet\">\n"
			+ "    <link href=\"favicon.ico\" type=\"image/x-icon\" rel=\"shortcut icon\">\n"
			+ "  </head>\n"
			+ "  <body>\n"
			+ "  <style>\n"
			+ "    tr:nth-child(2n) {\n"
			+ "      background-color:#eeeeee;\n"
			+ "    }\n"
			+ "    .oiv {\n"
			+ "      color:red;\n"
			+ "    }\n"
			+ "    .oic {\n"
			+ "      color:gray;\n"
			+ "      text-decoration:line-through;\n"
			+ "    }\n"
			+ "    .ic {\n"
			+ "      color:blue;\n"
			+ "    }\n"
			+ "    .tbl-hdr {\n"
			+ "      height:3em;\n"
			+ "      vertical-align:bottom;\n"
			+ "    }\n"
			+ "    #relay-list td {\n"
			+ "      white-space:pre;\n"
			+ "    }\n"
			+ "  </style>\n"
			+ "    <div class=\"center\">\n"
			+ "      <div class=\"main-column\">\n"
			+ "        <h2>Consensus Health</h2>\n"
			+ "        <br>\n"
			+ "        <p>This page shows statistics about the current "
			+ "consensus and votes to facilitate debugging of the "
			+ "directory consensus process.")
		if not include_relay_info:
			self.site.write("<br />This is the abbreviated page. The "
			+ "<a href=\"/consensus-health.html\">detailed page</a> "
			+ "which includes the (large) relay info table is also "
			+ "available.")
		self.site.write("</p>\n")
		
	#-----------------------------------------------------------------------------------------
	def _write_valid_after_time(self):
		"""
		Write the valid-after time of the downloaded consensus.
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"validafter\">\n" \
		+ "<h3><a href=\"#validafter\" class=\"anchor\">" \
		+ "Valid-after time</a></h3>\n" \
		+ "<br>\n" \
		+ "<p>Consensus was published ")

		if self.consensus.valid_after + self.consensus_expiry < datetime.datetime.now():
			self.site.write('<span class="oiv">'
			+ self.consensus.valid_after.isoformat().replace("T", " ")
			+ '</span>')
		else:
			self.site.write(self.consensus.valid_after.isoformat().replace("T", " "))

		self.site.write(". <i>Note that it takes up to 15 minutes to learn "
		+ "about new consensus and votes and process them.</i></p>\n")

		wrote_at_least_one_odd_consensus = False
		for dirauth_nickname in self.known_authorities:
			if dirauth_nickname not in self.consensuses or \
				self.consensuses[dirauth_nickname].valid_after != self.consensus.valid_after:

				if wrote_at_least_one_odd_consensus == False:
					wrote_at_least_one_odd_consensus = True

					self.site.write("<p>Unusual Authorities:</p>\n")
					self.site.write("<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
					+ "  <colgroup>\n"
					+ "    <col width=\"160\">\n"
					+ "    <col width=\"640\">\n"
					+ "  </colgroup>\n")

				self.site.write("  <tr>\n"
				+ "    <td>" + dirauth_nickname + "</td>\n")

				if dirauth_nickname not in self.consensuses:
					self.site.write("    <td class=\"oiv\">Consensus Not Present</td>\n"
					+ "  </tr>\n")
				else:
					self.site.write("    <td>")
					self.site.write(self.consensuses[dirauth_nickname].valid_after.isoformat().replace("T", " "))
					self.site.write("</td>")

				self.site.write("  </tr>\n")
		self.site.write("</table>\n")

	#-----------------------------------------------------------------------------------------
	def _write_signatures(self):
		"""
		Write the presence and method of each signature
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"signatures\">\n" 
		+ "<h3><a href=\"#signatures\" class=\"anchor\">" 
		+ "Signatures</a></h3>\n" 
		+ "<br>\n"
		+ "<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
		+ "  <colgroup>\n"
		+ "    <col width=\"160\">\n"
		+ "    <col width=\"230\">\n"
		+ "    <col width=\"410\">\n"
		+ "  </colgroup>\n")
   
		# XXX Should also write if the displayed consensus is out of date
		signingFPs = {sig.identity:sig.method for sig in self.consensus.signatures}
		for dirauth_nickname in self.known_authorities: 
			self.site.write("  <tr>\n" 
			+ "    <td>" + dirauth_nickname + "</td>\n")
			
			#Try and find a structure that has it's IP & Port
			authority = [r for r in self.consensus.routers.values() if r.nickname.lower() == dirauth_nickname and 'Authority' in r.flags]
			if not authority:
				authority = [d for d in self.consensus.directory_authorities if d.nickname.lower() == dirauth_nickname]
			if authority:
				authority = authority[0]
				self.site.write("    <td><a href=\"http://" + authority.address + ":" + str(authority.dir_port)
				+ "/tor/status-vote/current/consensus\">consensus</a> (<a href=\"http://" + authority.address 
				+ ":" + str(authority.dir_port) + "/tor/status-vote/current/consensus-microdesc\">microdesc</a>)"
				+ " <a href=\"http://" + authority.address + ":" + str(authority.dir_port)
				+ "/tor/status-vote/current/authority\">vote</a></td>\n")
			else:
				self.site.write("    <td colspan=\"2\" class=\"oiv\">Missing entirely from consensus</td>\n")
				
			if dirauth_nickname in [d.nickname.lower() for d in self.consensus.directory_authorities]:
				#The above structure is sufficient for getting the address & port
				# but we need this structure for the authority's fingerprint
				authority = [d for d in self.consensus.directory_authorities if d.nickname.lower() == dirauth_nickname][0]
				if authority.fingerprint in signingFPs:
					self.site.write("    <td>" + signingFPs[authority.fingerprint] + "</td>\n")
				elif authority.nickname.lower() in self.consensuses:
					self.site.write("    <td class=\"oiv\">Missing Signature! "
					+ "Valid-after time of auth's displayed consensus: "
					+ self.consensuses[authority.nickname.lower()].valid_after.isoformat().replace("T", " ")
					+ "</td>\n")
				else:
					self.site.write("    <td class=\"oiv\">Missing Signature, and "
					+ authority.nickname.lower() + " does not have a consensus available</td>\n")
			self.site.write("  </tr>\n")
		self.site.write("</table>\n")

	#-----------------------------------------------------------------------------------------
	def _write_known_flags(self):
		"""
		Write the lists of known flags.
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"knownflags\">\n"
		+ "<h3><a href=\"#knownflags\" class=\"anchor\">Known flags</a></h3>\n"
		+ "<br>\n"
		+ "<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
		+ "  <colgroup>\n"
		+ "    <col width=\"160\">\n"
		+ "    <col width=\"640\">\n"
		+ "  </colgroup>\n")
		for dirauth_nickname in self.known_authorities:
			if dirauth_nickname in self.votes:
				vote = self.votes[dirauth_nickname]
				self.site.write("  <tr>\n"
				+ "    <td>" + dirauth_nickname + "</td>\n"
				+ "    <td>known-flags");
				for knownFlag in vote.known_flags:
					self.site.write(" " + knownFlag)
				self.site.write("</td>\n" + "  </tr>\n")
			else:
				self.site.write("  <tr>\n"
				+ "    <td>" + dirauth_nickname + "</td>\n"
				+ "    <td class=\"oiv\">Vote Not Present</td>\n"
				+ "  </tr>\n")
		self.site.write("  <tr>\n"
		+ "    <td class=\"ic\">consensus</td>\n"
		+ "    <td class=\"ic\">known-flags")
		for knownFlag in self.consensus.known_flags:
			self.site.write(" " + knownFlag)
		self.site.write("</td>\n"
		+ "  </tr>\n"
		+ "</table>\n")

	#-----------------------------------------------------------------------------------------
	def _write_flag_thresholds(self):
		"""
		Write each dirauth's flag thresholds
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"flagthresholds\">\n"
		+ "<h3><a href=\"#flagthresholds\" class=\"anchor\">Flag Thresholds</a></h3>\n"
		+ "<br>\n"
		+ "<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
		+ "  <colgroup>\n"
		+ "    <col width=\"160\">\n"
		+ "    <col width=\"640\">\n"
		+ "  </colgroup>\n")
		for dirauth_nickname in self.known_authorities:
			if dirauth_nickname in self.votes:
				vote = self.votes[dirauth_nickname]
				self.site.write("  <tr>\n"
				+ "    <td>" + dirauth_nickname + "</td>\n"
				+ "    <td>flag-thresholds");
				for k in vote.flag_thresholds:
					self.site.write(" " + k + "=" + str(vote.flag_thresholds[k]))
				self.site.write("</td>\n" + "  </tr>\n")
			else:
				self.site.write("  <tr>\n"
				+ "    <td>" + dirauth_nickname + "</td>\n"
				+ "    <td class=\"oiv\">Vote Not Present</td>\n"
				+ "  </tr>\n")
		self.site.write("</table>\n")

	#-----------------------------------------------------------------------------------------
	def _write_number_of_relays_voted_about(self, linkToGraph):
		"""
		Write the number of relays voted about.
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"numberofrelays\">\n"
		+ "<h3><a href=\"#numberofrelays\" class=\"anchor\">"
		+ "Number of relays voted about</a></h3>\n")
		if linkToGraph:
			self.site.write("<p>\n"
			+ "  You can also view <a href=\"graphs.html\">historical voting graphs</a>.\n"
			+ "</p>\n")
		else:
			self.site.write("<br />\n")
		self.site.write("<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
		+ "  <colgroup>\n"
		+ "    <col width=\"160\">\n"
		+ "    <col width=\"320\">\n"
		+ "    <col width=\"320\">\n"
		+ "  </colgroup>\n")
		if not self.votes:
		  self.site.write("  <tr><td>(No votes.)</td><td></td><td></td></tr>\n")
		else:
			for dirauth_nickname in self.known_authorities:
				if dirauth_nickname in self.votes:
					vote = self.votes[dirauth_nickname]
					runningRelays = 0
					for r in vote.routers.values():
						if u'Running' in r.flags:
							runningRelays += 1
					self.site.write("  <tr>\n"
					+ "    <td>" + dirauth_nickname + "</td>\n"
					+ "    <td>" + str(len(vote.routers)) + " total</td>\n"
					+ "    <td>" + str(runningRelays) + " Running</td>\n"
					+ "  </tr>\n")
				else:
					self.site.write("  <tr>\n"
					+ "    <td>" + dirauth_nickname + "</td>\n"
					+ "    <td colspan=\"2\"><span class=\"oiv\">Vote Not Present<span></td>\n"
					+ "  </tr>\n")
		runningRelays = 0
		for r in self.consensus.routers.values():
			if u'Running' in r.flags:
				runningRelays += 1
		self.site.write("  <tr>\n"
		+  "    <td class=\"ic\">consensus</td>\n"
		+  "    <td/>\n"
		+  "    <td class=\"ic\">" + str(runningRelays) + " Running</td>\n"
		+  "  </tr>\n"
		+  "</table>\n")		

	#-----------------------------------------------------------------------------------------
	def _write_consensus_methods(self):
		"""
		Write the supported consensus methods of directory authorities and
		the resulting consensus method.
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"consensusmethods\">\n"
		+ "<h3><a href=\"#consensusmethods\" class=\"anchor\">"
		+ "Consensus methods</a></h3>\n"
		+ "<br>\n"
		+ "<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
		+ "  <colgroup>\n"
		+ "    <col width=\"160\">\n"
		+ "    <col width=\"640\">\n"
		+ "  </colgroup>\n")		
		if not self.votes:
			self.site.write("  <tr><td>(No votes.)</td><td></td></tr>\n")
		else:
			for dirauth_nickname in self.known_authorities:
				if dirauth_nickname in self.votes:
					vote = self.votes[dirauth_nickname]
					usedMethod = self.consensus.consensus_method

					if usedMethod in vote.consensus_methods:
						self.site.write("  <tr>\n"
						+ "    <td>" + dirauth_nickname + "</td>\n"
						+ "    <td>consensus-methods")
						for cm in vote.consensus_methods:
							self.site.write(" " + str(cm))
						self.site.write("</td>\n"
						+ "  </tr>\n")
					else:
						self.site.write("  <tr>\n"
						+ "    <td class=\"oiv\">"
						+	   dirauth_nickname + "</td>\n"
						+ "    <td class=\"oiv\">consensus-methods")
						for cm in vote.consensus_methods:
							self.site.write(" " + str(cm))
						self.site.write("</td>\n"
						+ "  </tr>\n")
				else:
					self.site.write("  <tr>\n"
					+ "    <td>" + dirauth_nickname + "</td>\n"
					+ "    <td class=\"oiv\">Vote Not Present</td>\n"
					+ "  </tr>\n")
		self.site.write("  <tr>\n"
		+ "    <td class=\"ic\">consensus</td>\n"
		+ "    <td class=\"ic\">consensus-method "
		+ str(self.consensus.consensus_method)
		+ "    </td>\n"
		+ "  </tr>\n"
		+ "</table>\n")

	#-----------------------------------------------------------------------------------------
	def _write_recommended_versions(self):
		"""
		Write recommended versions.
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"recommendedversions\">\n"
		+ "<h3><a href=\"#recommendedversions\" class=\"anchor\">"
		+ "Recommended versions</a></h3>\n"
		+ "<br>\n"
		+ "<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
		+ "  <colgroup>\n"
		+ "    <col width=\"160\">\n"
		+ "    <col width=\"640\">\n"
		+ "  </colgroup>\n")
		if not self.votes:
			self.site.write("  <tr><td>(No votes.)</td><td></td></tr>\n")
		else:
			for dirauth_nickname in self.known_authorities:
				if dirauth_nickname in self.votes:
					vote = self.votes[dirauth_nickname]
				
					if vote.client_versions:
						self.site.write("  <tr>\n"
						+ "    <td>" + dirauth_nickname + "</td>\n"
						+ "    <td>client-versions ")
						self.site.write(", ".join([(str(v) if v in self.consensus.client_versions else "<span class=\"oiv\">" + str(v) + "</span>")
							for v in vote.client_versions]))
						self.site.write("".join([(", <span class=\"oiv\"><s>" + str(v) + "</s></span>")
							for v in self.consensus.client_versions if v not in vote.client_versions]))
						self.site.write("</td>\n"
						+ "  </tr>\n")
					if vote.server_versions:
						self.site.write("  <tr>\n"
						+ "    <td>" + dirauth_nickname + "</td>\n"
						+ "    <td>server-versions ")
						self.site.write(", ".join([(str(v) if v in self.consensus.server_versions else "<span class=\"oiv\">" + str(v) + "</span>")
							for v in vote.server_versions]))
						self.site.write("".join([(", <span class=\"oiv\"><s>" + str(v) + "</s></span>")
							for v in self.consensus.server_versions if v not in vote.server_versions]))
						self.site.write("</td>\n"
						+ "  </tr>\n")
				else:
					self.site.write("  <tr>\n"
					+ "    <td>" + dirauth_nickname + "</td>\n"
					+ "    <td class=\"oiv\">Vote Not Present</td>\n"
					+ "  </tr>\n")
		self.site.write("  <tr>\n"
		+ "    <td class=\"ic\">consensus</td>\n"
		+ "    <td class=\"ic\">client-versions ")
		self.site.write(", ".join([str(v) for v in self.consensus.client_versions]))
		self.site.write("</td>\n"
		+ "  </tr>\n"
		+ "  <tr>\n"
		+ "    <td></td>\n"
		+ "    <td class=\"ic\">server-versions ")
		self.site.write(", ".join([str(v) for v in self.consensus.server_versions]))
		self.site.write("</td>\n"
		+ "  </tr>\n"
		+ "</table>\n")

	#-----------------------------------------------------------------------------------------
	def _write_consensus_parameters(self):
		"""
		Write consensus parameters.
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"consensusparams\">\n"
		+ "<h3><a href=\"#consensusparams\" class=\"anchor\">Consensus parameters</a></h3>\n"
		+ "<br>\n"
		+ "<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
		+ "  <colgroup>\n"
		+ "    <col width=\"160\">\n"
		+ "    <col width=\"640\">\n"
		+ "  </colgroup>\n")

		if not self.votes:
			self.site.write("  <tr><td>(No votes.)</td><td></td></tr>\n")
		else:
			for dirauth_nickname in self.known_authorities:
				if dirauth_nickname in self.votes:
					vote = self.votes[dirauth_nickname]
					conflictOrInvalid = []
					if vote.params:
						for p in vote.params:
							if (p not in self.known_params and not p.startswith('bwauth')) or \
							   p not in self.consensus.params or \
							   self.consensus.params[p] != vote.params[p]:
								conflictOrInvalid.append(p)
								break
					
					if conflictOrInvalid:
						self.site.write("  <tr>\n"
						+ "    <td class=\"oiv\">" + dirauth_nickname + "</td>\n"
						+ "    <td>params")
						for p in vote.params:
							if p in conflictOrInvalid:
								self.site.write(" <span class=\"oiv\">" + p + "=" + str(vote.params[p]) + "</span>")
							else:
								self.site.write(" " + p + "=" + str(vote.params[p]))
						self.site.write("</td>\n"
						+ "  </tr>\n")
					else:
						self.site.write("  <tr>\n"
						+  "    <td>" + dirauth_nickname + "</td>\n"
						+  "    <td>params")
						for p in vote.params:
							self.site.write(" " + p + "=" + str(vote.params[p]))
						self.site.write(  "</td>\n"
						+ "  </tr>\n")
				else:
					self.site.write("  <tr>\n"
					+ "    <td>" + dirauth_nickname + "</td>\n"
					+ "    <td class=\"oiv\">Vote Not Present</td>\n"
					+ "  </tr>\n")

		self.site.write("  <tr>\n"
		+ "    <td class=\"ic\">consensus</td>\n"
		+ "    <td class=\"ic\">params")
		for p in self.consensus.params:
			self.site.write(" " + p + "=" + str(self.consensus.params[p]))
		self.site.write("    </td>\n"
		+ "  </tr>\n"
		+ "</table>\n")

	#-----------------------------------------------------------------------------------------
	def getKeySize(self, key):
		key = key.replace("-----BEGIN RSA PUBLIC KEY-----", "")
		key = key.replace("-----END RSA PUBLIC KEY-----", "")
		key = key.replace("\n", "")
		keyDER = b64decode(key)
		keyPub = RSA.importKey(keyDER)
		return str(keyPub.size() + 1)

	def _write_authority_keys(self):
		"""
		Write authority keys and their expiration dates.
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"authoritykeys\">\n"
		+ "<h3><a href=\"#authoritykeys\" class=\"anchor\">"
		+ "Authority keys</a></h3>\n"
		+ "<br>\n"
		+ "<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
		+ "  <colgroup>\n"
		+ "    <col width=\"160\">\n"
		+ "    <col width=\"300\">\n"
		+ "    <col width=\"170\">\n"
		+ "    <col width=\"170\">\n"
		+ "  </colgroup>\n"
		+ "  <tr>\n"
		+ "    <th>Name</th>"
		+ "    <th>Expiry</th>"
		+ "    <th>Identity Key Len.</th>"
		+ "    <th>Signing Key Len.</th>"
		+ "  </tr>\n")

		if not self.votes:
			self.site.write("  <tr><td>(No votes.)</td><td></td></tr>\n")
		else:
			for dirauth_nickname in self.known_authorities:
				if dirauth_nickname in self.votes:
					vote = self.votes[dirauth_nickname]

					voteDirKeyExpires = vote.directory_authorities[0].key_certificate.expires
					if voteDirKeyExpires - self.directory_key_warning_time < datetime.datetime.now():
						self.site.write("  <tr>\n"
						+ "    <td class=\"oiv\">" + dirauth_nickname + "</td>\n"
						+ "    <td class=\"oiv\">"
						+ voteDirKeyExpires.isoformat().replace("T", " ") + "</td>\n")
					else:
						self.site.write("  <tr>\n"
						+ "    <td>" + dirauth_nickname + "</td>\n"
						+ "    <td>"
						+ voteDirKeyExpires.isoformat().replace("T", " ") + "</td>\n")

					self.site.write("    <td>" + self.getKeySize(vote.directory_authorities[0].key_certificate.identity_key) + "</td>\n"
					+ "    <td>" + self.getKeySize(vote.directory_authorities[0].key_certificate.signing_key) + "</td>\n"
					+ "  </tr>\n");
				else:
					self.site.write("  <tr>\n"
					+ "    <td>" + dirauth_nickname + "</td>\n"
					+ "    <td colspan=\"3\"><span class=\"oiv\">Vote Not Present<span></td>\n"
					+ "  </tr>\n")

			self.site.write("</table>\n"
			+ "<br>\n"
			+ "<p><i>Note that expiration dates of any legacy keys are "
			+ "not included in votes and therefore not listed here!</i>"
			+ "</p>\n")

	#-----------------------------------------------------------------------------------------
	def sharedRandomToStr(self, sr):
		s = "["
		s += "V:" + str(sr.version) + " "
		s += "A:" + str(sr.algorithm) + " "
		s += "C:" + sr.commit if sr.commit else "<span class=\"oiv\">(Empty)</span>"
		s += "R:" + sr.reveal if sr.reveal else "<span class=\"oiv\">(Empty)</span>"
		return s + "]"
	def _write_shared_random(self):
		"""
		Write the shared random information of each directory authority
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"sharedrandom\">\n"
		+ "<h3><a href=\"#sharedrandom\" class=\"anchor\">"
		+ "Shared Random</a></h3>\n"
		+ "<br>\n"
		+ "<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
		+ "  <colgroup>\n"
		+ "    <col width=\"140\">\n"
		+ "    <col width=\"180\">\n"
		+ "    <col width=\"480\">\n"
		+ "  </colgroup>\n")
		if not self.votes:
			self.site.write("  <tr><td>(No votes.)</td><td></td></tr>\n")
		else:
			for dirauth_nickname in self.known_authorities:
				if dirauth_nickname in self.votes:
					vote = self.votes[dirauth_nickname]

					if vote.directory_authorities[0].is_shared_randomness_participate:
						prev_error = ""
						cur_error = ""
						if vote.directory_authorities[0].shared_randomness_previous_reveal_count != self.consensus.shared_randomness_previous_reveal_count or \
						   vote.directory_authorities[0].shared_randomness_previous_value != self.consensus.shared_randomness_previous_value:
							prev_error = " class=\"oiv\""
						if vote.directory_authorities[0].shared_randomness_current_reveal_count != self.consensus.shared_randomness_current_reveal_count or \
						   vote.directory_authorities[0].shared_randomness_current_value != self.consensus.shared_randomness_current_value:
							cur_error = " class=\"oiv\""
						self.site.write("  <tr>\n"
						+ "    <td>" + dirauth_nickname + "</td>\n"
						+ "    <td>Previous</td>\n"
						+ "    <td" + prev_error + ">" + str(vote.directory_authorities[0].shared_randomness_previous_reveal_count)
						+ " " + str(vote.directory_authorities[0].shared_randomness_previous_value) + "</td>\n"
						+ "  </tr>\n"
						+ "  <tr>\n"
						+ "    <td></td>\n"
						+ "    <td>Current</td>\n"
						+ "    <td" + cur_error + ">" + str(vote.directory_authorities[0].shared_randomness_current_reveal_count)
						+ " " + str(vote.directory_authorities[0].shared_randomness_current_value) + "</td>\n"
						+ "</td>\n"
						+ "  </tr>\n"
						+ "  <tr>\n"
						+ "    <td></td>\n"
						+ "    <td>Commitments</td>\n"
						+ "    <td style=\"font-size:x-small\">" + ", <br />".join([self.sharedRandomToStr(x) for x in vote.directory_authorities[0].shared_randomness_commitments]) + "</td>\n"
						+ "  </tr>\n")
					else:
						self.site.write("  <tr>\n"
						+ "    <td><span class=\"oiv\">"
						+	   dirauth_nickname + "</span></td>\n"
						+ "    <td colspan=\"2\"><span class=\"oiv\">Does not participate"
						+ "</span></td>\n"
						+ "  </tr>\n")
				else:
					self.site.write("  <tr>\n"
					+ "    <td>" + dirauth_nickname + "</td>\n"
					+ "    <td colspan=\"2\"><span class=\"oiv\">Vote Not Present<span></td>\n"
					+ "  </tr>\n")
		self.site.write("  <tr>\n"
		+ "    <td class=\"ic\">consensus</td>\n"
		+ "    <td class=\"ic\">Previous</td>\n"
		+ "    <td class=\"ic\">" + str(self.consensus.shared_randomness_previous_reveal_count)
		+ " " + str(self.consensus.shared_randomness_previous_value) + "</td>\n"
		+ "  </tr>\n"
		+ "  <tr>\n"
		+ "    <td></td>\n"
		+ "    <td class=\"ic\">Current</td>\n"
		+ "    <td class=\"ic\">" + str(self.consensus.shared_randomness_current_reveal_count)
		+ " " + str(self.consensus.shared_randomness_current_value) + "</td>\n"
		+ "  </tr>\n"
		+ "</table>\n")

	#-----------------------------------------------------------------------------------------
	def protocolsToString(self, keys, v, c=None):
		s = ""
		for k in keys:
			s += k + "="
			if c and c[k] != v[k]:
				s += "<span class=\"oiv\">"
			s += ",".join([str(i) for i in v[k]])
			if c and c[k] != v[k]:
				s += "</span>"
			s += " "
		return s
	def _write_protocols(self):
		"""
		Write the recommended and required protocols
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"protocols\">\n"
		+ "<h3><a href=\"#protocols\" class=\"anchor\">"
		+ "Protocols</a></h3>\n"
		+ "<br>\n"
		+ "<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
		+ "  <colgroup>\n"
		+ "    <col width=\"140\">\n"
		+ "    <col width=\"180\">\n"
		+ "    <col width=\"480\">\n"
		+ "  </colgroup>\n")		
		if not self.votes:
			self.site.write("  <tr><td>(No votes.)</td><td></td></tr>\n")
		else:
			protocol_keys = set()
			for dirauth_nickname in self.known_authorities:
				if dirauth_nickname in self.votes:
					vote = self.votes[dirauth_nickname]
					protocol_keys = protocol_keys.union(vote.recommended_client_protocols.keys())
					protocol_keys = protocol_keys.union(vote.required_client_protocols.keys())
					protocol_keys = protocol_keys.union(vote.recommended_relay_protocols.keys())
					protocol_keys = protocol_keys.union(vote.required_relay_protocols.keys())
			protocol_keys = list(protocol_keys)
			protocol_keys.sort()
			for dirauth_nickname in self.known_authorities:
				if dirauth_nickname in self.votes:
					vote = self.votes[dirauth_nickname]

					self.site.write("  <tr>\n"
					+ "    <td>" + dirauth_nickname + "</td>\n"
					+ "    <td>Recommended Client</td>\n"
					+ "    <td>" + self.protocolsToString(protocol_keys, vote.recommended_client_protocols, self.consensus.recommended_client_protocols) + "</td>\n"
					+ "  </tr>\n"
					+ "  <tr>\n"
					+ "    <td></td>\n"
					+ "    <td>Required Client</td>\n"
					+ "    <td>" + self.protocolsToString(protocol_keys, vote.required_client_protocols, self.consensus.required_client_protocols) + "</td>\n"
					+ "  </tr>\n"
					+ "  <tr>\n"
					+ "    <td></td>\n"
					+ "    <td>Recommended Relay</td>\n"
					+ "    <td>" + self.protocolsToString(protocol_keys, vote.recommended_relay_protocols, self.consensus.recommended_relay_protocols) + "</td>\n"
					+ "  </tr>\n"
					+ "  <tr>\n"
					+ "    <td></td>\n"
					+ "    <td>Required Relay</td>\n"
					+ "    <td>" + self.protocolsToString(protocol_keys, vote.required_relay_protocols, self.consensus.required_relay_protocols) + "</td>\n"
					+ "  </tr>\n")
				else:
					self.site.write("  <tr>\n"
					+ "    <td>" + dirauth_nickname + "</td>\n"
					+ "    <td colspan=\"2\" class=\"oiv\">Vote Not Present</td>\n"	
					+ "  </tr>\n")
			self.site.write("  <tr>\n"
			+ "    <td class=\"ic\">consensus</td>\n"
			+ "    <td class=\"ic\">Recommended Client</td>\n"
			+ "    <td class=\"ic\">" + self.protocolsToString(protocol_keys, self.consensus.recommended_client_protocols) + "</td>\n"
			+ "  </tr>\n"
			+ "  <tr>\n"
			+ "    <td></td>\n"
			+ "    <td class=\"ic\">Required Client</td>\n"
			+ "    <td class=\"ic\">" + self.protocolsToString(protocol_keys, self.consensus.required_client_protocols) + "</td>\n"
			+ "  </tr>\n"
			+ "  <tr>\n"
			+ "    <td></td>\n"
			+ "    <td class=\"ic\">Recommended Relay</td>\n"
			+ "    <td class=\"ic\">" + self.protocolsToString(protocol_keys, self.consensus.recommended_relay_protocols) + "</td>\n"
			+ "  </tr>\n"
			+ "  <tr>\n"
			+ "    <td></td>\n"
			+ "    <td class=\"ic\">Required Relay</td>\n"
			+ "    <td class=\"ic\">" + self.protocolsToString(protocol_keys, self.consensus.required_relay_protocols) + "</td>\n"
			+ "  </tr>\n"
			+ "</table>\n")

	#-----------------------------------------------------------------------------------------
	def _write_bandwidth_scanner_status(self, linkToGraph):
		"""
		Write the status of bandwidth scanners and results being contained in votes.
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"bwauthstatus\">\n"
		+ "<h3><a href=\"#bwauthstatus\" class=\"anchor\">"
		+ "Bandwidth scanner status</a></h3>\n")
		if linkToGraph:
			self.site.write("<p>\n"
			+ "  You can also view <a href=\"graphs.html\">historical Bandwidth Authority graphs</a>.\n"
			+ "</p>\n")
		else:
			self.site.write("<br />\n")
		self.site.write("<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
		+ "  <colgroup>\n"
		+ "    <col width=\"160\">\n"
		+ "    <col width=\"640\">\n"
		+ "  </colgroup>\n")
		if not self.votes:
			self.site.write("  <tr><td>(No votes.)</td><td></td></tr>\n")
		else:
			for dirauth_nickname in self.votes:
				vote = self.votes[dirauth_nickname]
				
				bandwidthWeights = 0
				for r in vote.routers.values():
					if r.measured >= 0L:
						bandwidthWeights += 1
				
				if bandwidthWeights > 0:
					self.site.write("  <tr>\n"
					+ "    <td>" + dirauth_nickname + "</td>\n"
					+ "    <td>" + str(bandwidthWeights)
					+ " Measured values in w lines</td>\n"
					+ "  </tr>\n")
			for dirauth_nickname in self.bandwidth_authorities:
				if dirauth_nickname not in self.votes:
					self.site.write("  <tr>\n"
					+ "    <td>" + dirauth_nickname + "</td>\n"
					+ "    <td class=\"oiv\">Missing vote</td>\n"
					+ "  </tr>\n")

		self.site.write("</table>\n")

	#-----------------------------------------------------------------------------------------
	def _write_fallback_directory_status(self, linkToGraph):
		"""
		Write the status of the fallback directory mirrors
		"""
		if self.config['ignore_fallback_authorities']:
				return

		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"fallbackdirstatus\">\n"
		+ "<h3><a href=\"#fallbackdirstatus\" class=\"anchor\">"
		+ "Fallback Directory status</a></h3>\n")
		if linkToGraph:
			self.site.write("<p>\n"
			+ "  You can also view <a href=\"graphs.html\">historical Fallback Directory graphs</a>.\n"
			+ "</p>\n")
		else:
			self.site.write("<br />\n")
		self.site.write("<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
		+ "  <colgroup>\n"
		+ "    <col width=\"160\">\n"
		+ "    <col width=\"640\">\n"
		+ "  </colgroup>\n")
		if not self.consensus:
			self.site.write("  <tr><td>(No consensus.)</td><td></td></tr>\n")
		else:
			fallback_dirs_running = 0
			fallback_dirs_notrunning = 0
			fallback_dirs_missing = 0

			for relay_fp in self.consensus.routers:
				if relay_fp in self.fallback_dirs and self.consensus.routers[relay_fp].flags and 'Running' in self.consensus.routers[relay_fp].flags:
					fallback_dirs_running += 1
				elif relay_fp in self.fallback_dirs:
					fallback_dirs_notrunning += 1
			fallback_dirs_missing = len(self.fallback_dirs) - fallback_dirs_notrunning - fallback_dirs_running
				
			self.site.write("  <tr>\n"
			+ "    <td>Running</td>\n"
			+ "    <td>" + str(fallback_dirs_running) + "</td>\n"
			+ "  </tr>\n")
			self.site.write("  <tr>\n"
			+ "    <td>Not Running</td>\n"
			+ "    <td>" + str(fallback_dirs_notrunning) + "</td>\n"
			+ "  </tr>\n")
			self.site.write("  <tr>\n"
			+ "    <td>Missing</td>\n"
			+ "    <td>" + str(fallback_dirs_missing) + "</td>\n"
			+ "  </tr>\n")

		self.site.write("</table>\n")

	#-----------------------------------------------------------------------------------------
	def _write_authority_versions(self):
		"""
		Write directory authority versions.
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"authorityversions\">\n"
		+ "<h3><a href=\"#authorityversions\" class=\"anchor\">"
		+ "Authority versions</a></h3>\n"
		+ "<br>\n")

		authorityVersions = [(r.nickname.lower(), r.version) for r in self.consensus.routers.values() if 'Authority' in r.flags]
		if not authorityVersions:
			self.site.write("<p>(No relays with Authority flag found.)</p>\n")
		else:
			self.site.write("<table border=\"0\" cellpadding=\"4\" "
			+ "cellspacing=\"0\" summary=\"\">\n"
			+ "  <colgroup>\n"
			+ "    <col width=\"160\">\n"
			+ "    <col width=\"640\">\n"
			+ "  </colgroup>\n")
			for a in authorityVersions:
				self.site.write("  <tr>\n"
				+ "    <td>" + a[0] + "</td>\n"
				+ "    <td>" + str(a[1]) + "</td>\n"
				+ "  </tr>\n")
			self.site.write("</table>\n"
			+ "<br>\n"
			+ "<p><i>Note that this list of relays with the "
			+ "Authority flag may be different from the list of v3 "
			+ "directory authorities!</i></p>\n")

	#-----------------------------------------------------------------------------------------
	def _write_download_statistics(self):
		"""
		Write some download statistics.
		"""
		f = open(os.path.join(os.path.dirname(__file__), 'out', 'download-stats.csv'), 'r')
		lines = f.readlines()
		f.close()

		cutoff = int(time.time() * 1000) - (7 * 24 * 60 * 60 * 1000)
		downloadData = {}
		for l in lines:
			parts = l.split(',')
			parts[0] = parts[0].lower()
			if int(parts[1]) < cutoff:
				continue
			if parts[0] not in downloadData:
				downloadData[parts[0]] = []
			downloadData[parts[0]].append(int(parts[2].strip()))

		maxDownloadsForAnyAuthority = 0
		for a in downloadData:
			downloadData[a].sort()
			maxDownloadsForAnyAuthority = max(len(downloadData[a]), maxDownloadsForAnyAuthority)

		def getPercentile(dataset, percentile):
			index = (percentile * (len(dataset) - 1)) / 100
			return str(dataset[index])

		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"downloadstats\">\n"
		+ "<h3><a href=\"#downloadstats\" class=\"anchor\">"
		+ "Consensus download statistics</a></h3>\n"
		+ "<br>\n"
		+ "<p>The following table contains statistics on "
		+ "consensus download times in milliseconds over the last 7 "
		+ "days:</p>\n"
		+ "<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
		+ "  <colgroup>\n"
		+ "    <col width=\"160\">\n"
		+ "    <col width=\"100\">\n"
		+ "    <col width=\"100\">\n"
		+ "    <col width=\"100\">\n"
		+ "    <col width=\"100\">\n"
		+ "    <col width=\"100\">\n"
		+ "    <col width=\"100\">\n"
		+ "  </colgroup>\n"
		+ "  <tr><th>Authority</th>\n"
		+ "    <th>Minimum</th>\n"
		+ "    <th>1st Quartile</th>\n"
		+ "    <th>Median</th>\n"
		+ "    <th>3rd Quartile</th>\n"
		+ "    <th>Maximum</th>\n"
		+ "    <th>Timeouts</th>\n"
		+ "  </tr>\n");
		
		for dirauth_nickname in self.known_authorities:
			if dirauth_nickname not in downloadData:
				self.site.write("  <tr>\n"
				+ "     <td colspan=\"7\"><span class=\"oiv\">"
				+ dirauth_nickname + " not present in download statistics"
				+ "</span></td>\n"
				+ "  </tr>\n");
			else:
				self.site.write("  <tr>\n"
				+  "    <td>" + dirauth_nickname + "</td>\n"
				+  "    <td>"
				+ getPercentile(downloadData[dirauth_nickname], 0) + "</td>\n"
				+  "    <td>"
				+ getPercentile(downloadData[dirauth_nickname], 25) + "</td>\n"
				+  "    <td>"
				+ getPercentile(downloadData[dirauth_nickname], 50) + "</td>\n"
				+  "    <td>"
				+ getPercentile(downloadData[dirauth_nickname], 75) + "</td>\n"
				+  "    <td>"
				+ getPercentile(downloadData[dirauth_nickname], 100) + "</td>\n"
				+  "    <td>"
				+ str(maxDownloadsForAnyAuthority - len(downloadData[dirauth_nickname])) + "</td>\n"
				+ "  </tr>\n");
		self.site.write("</table>\n");

	#-----------------------------------------------------------------------------------------
	def _write_relay_info_summary(self):
		"""
		Write the relay flag summary
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"overlap\">\n"
		+ "<h3><a href=\"#overlap\" class=\"anchor\">Overlap "
		+ "between votes and consensus</a></h3>\n"
		+ "<br>\n"
		+ "<p>The semantics of columns is as follows:</p>\n"
		+ "<ul>\n"
		+ "  <li><b>In vote and consensus:</b> Flag in vote matches flag in consensus, or relay is not listed in "
		+ "consensus (because it doesn't have the Running flag)</li>\n"
		+ "  <li><b><span class=\"oiv\">Only in vote:</span></b> Flag in vote, but missing in the "
		+ "consensus, because there was no majority for the flag or "
		+ "the flag was invalidated (e.g., Named gets invalidated by Unnamed)</li>\n"
		+ "  <li><b><span class=\"oic\">Only in consensus:</span></b> Flag in consensus, but missing "
		+ "in a vote of a directory authority voting on this flag</li>\n"
		+ "</ul>\n"
		+ "<br>\n"
		+ "<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
		+ "  <colgroup>\n"
		+ "    <col width=\"160\">\n"
		+ "    <col width=\"210\">\n"
		+ "    <col width=\"210\">\n"
		+ "    <col width=\"210\">\n"
		+ "  </colgroup>\n"
		+ "  <tr>\n" 
		+ "    <td></td>\n"
		+ "    <td><b>Only in vote</b></td>"
		+ "    <td><b>In vote and consensus</b></td>"
		+ "    <td><b>Only in consensus</b></td>\n")

		allFingerprints = set()
		for vote in self.votes.values():
			allFingerprints.update(vote.routers.keys())
		allFingerprints.update(self.consensus.routers.keys())

		flagsAgree = {}
		flagsLost = {}
		flagsMissing = {}
	
		for relay_fp in allFingerprints:
			consensusFlags = [] if relay_fp not in self.consensus.routers else self.consensus.routers[relay_fp].flags

			for dirauth_nickname in self.votes:
				vote = self.votes[dirauth_nickname]

				if relay_fp in vote.routers:
					for kf in self.consensus.known_flags:
						workingSet = None
						if kf in vote.routers[relay_fp].flags:
							if consensusFlags == [] or kf in consensusFlags:
								workingSet = flagsAgree
							else:
								workingSet = flagsLost
						elif consensusFlags != [] and kf in vote.known_flags and kf in consensusFlags:
							workingSet = flagsMissing

						if workingSet is not None:
							#Index into Dict, or make a new dict
							if dirauth_nickname in workingSet:
								workingEntry = workingSet[dirauth_nickname]
							else:
								workingSet[dirauth_nickname] = {}
								workingEntry = workingSet[dirauth_nickname]
							#Increment (or start at 1)
							if kf in workingEntry:
								workingEntry[kf] += 1
							else:
								workingEntry[kf] = 1

		for dirauth_nickname in self.known_authorities:
			if dirauth_nickname in self.votes:
				vote = self.votes[dirauth_nickname]

				i = 0
				for kf in vote.known_flags:
					self.site.write("  <tr>\n"
					+  "    <td>" + (dirauth_nickname if i == 0 else "")
					+ "</td>\n")
					i += 1

					if dirauth_nickname in flagsLost and kf in flagsLost[dirauth_nickname]:
						self.site.write("    <td class=\"oiv\"> "
						+ str(flagsLost[dirauth_nickname][kf]) + " " + kf
						+ "</td>\n")
					else:
						self.site.write("    <td></td>\n")

					if dirauth_nickname in flagsAgree and kf in flagsAgree[dirauth_nickname]:
						self.site.write("    <td>" + str(flagsAgree[dirauth_nickname][kf])
						+ " " + kf + "</td>\n")
					else:
						self.site.write("    <td></td>\n")

					if dirauth_nickname in flagsMissing and kf in flagsMissing[dirauth_nickname]:
						self.site.write("    <td><span class=\"oic\">"
						+ str(flagsMissing[dirauth_nickname][kf]) + " " + kf
						+ "</span></td>\n")
					else:
						self.site.write("    <td></td>\n")
					self.site.write("  </tr>\n")
			else:
				self.site.write("  <tr>\n"
				+ "    <td>" + dirauth_nickname + "</td>\n"
				+ "    <td colspan=\"3\"><span class=\"oiv\">Vote Not Present<span></td>\n"
				+ "  </tr>\n")
		self.site.write("</table>\n")

	#-----------------------------------------------------------------------------------------
	def _write_relay_info_pointer(self):
		"""
		Write a pointer to where the huge table is located
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"relayinfo\">\n"
		+ "<h3><a href=\"#relayinfo\" class=\"anchor\">Relay info</a></h3>\n"
		+ "<br>\n"
		+ "<p>Looking for the (huge) relay info table? It's been moved to the <a "
		+ "href=\"/consensus-health.html\">detailed page</a> to speed up this page.</p>\n")
	def _write_relay_info_table(self):
		"""
		Write the (huge) table containing relay info contained in votes and
		the consensus for each relay.
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"relayinfo\">\n"
		+ "<h3><a href=\"#relayinfo\" class=\"anchor\">Relay info</a></h3>\n"
		+ "<br>\n"
		+ "<p>The semantics of flags written in the table is similar to the table above:</p>\n"
		+ "<ul>\n"
		+ "  <li><b>In vote and consensus:</b> Flag in vote matches flag in consensus, or relay is not listed in "
		+ "consensus (because it doesn't have the Running flag)</li>\n"
		+ "  <li><b><span class=\"oiv\">Only in vote:</span></b> Flag in vote, but missing in the "
		+ "consensus, because there was no majority for the flag or "
		+ "the flag was invalidated (e.g., Named gets invalidated by Unnamed)</li>\n"
		+ "  <li><b><span class=\"oic\">Only in consensus:</span></b> Flag in consensus, but missing "
		+ "in a vote of a directory authority voting on this flag</li>\n"
		+ "  <li><b><span class=\"ic\">In consensus:</span></b> Flag in consensus</li>\n"
		+ "</ul>\n"
		+ "<br>\n"
		+ "<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" id=\"relay-list\" summary=\"\">\n"
		+ "  <colgroup>\n"
		+ "    <col width=\"120\">\n"
		+ "    <col width=\"80\">\n")
		for dirauth_nickname in self.votes:
			self.site.write("    <col width=\"" + str(640 / len(self.votes)) + "\">\n")
		self.site.write("  </colgroup>\n")

		allRelays = {}
		for dirauth_nickname in self.votes:
			for relay_fp in self.votes[dirauth_nickname].routers:
				allRelays[relay_fp] = self.votes[dirauth_nickname].routers[relay_fp].nickname

		for relay_fp in self.consensus.routers:
			allRelays[relay_fp] = self.consensus.routers[relay_fp].nickname

		linesWritten = 0
		sortedKeys = allRelays.keys()
		sortedKeys.sort()
		for relay_fp in sortedKeys:
			if linesWritten % 10 == 0:
				self._write_relay_info_tableHeader()
			linesWritten += 1
			self._write_relay_info_tableRow(relay_fp, allRelays[relay_fp])

		self.site.write("</table>\n")

	#-----------------------------------------------------------------------------------------	
	def _write_relay_info_tableHeader(self):
		"""
		Write the table header that is repeated every ten relays and that
		contains the directory authority names.
		"""
		self.site.write("  <tr class=\"tbl-hdr\">\n    <th>Fingerprint</th>\n    <th>Nickname</th>\n")
		for dirauth_nickname in self.votes:
			shortNickname = dirauth_nickname[0:5] + "." if len(dirauth_nickname) > 6 else dirauth_nickname
			self.site.write("    <th>" + shortNickname + "</th>\n")
		self.site.write("    <th>consensus</th>\n  </tr>\n")

	#-----------------------------------------------------------------------------------------
	def _write_relay_info_tableRow(self, relay_fp, relay_nickname):
		"""
		Write a single row in the table of relay info.
		"""
		self.site.write("  <tr>\n")
		if relay_fp in self.consensus.routers and \
			"Named" in self.consensus.routers[relay_fp].flags and \
			 relay_nickname[0].isdigit():
			self.site.write("    <td id=\"" + relay_fp + "\">" \
			+ relay_fp.substring(0, 8) \
			+ "<br /><span style=\"tiny\">" \
			+ relay_fp \
			+ "</span></td>\n")
		else:
			self.site.write("    <td id=\"" + relay_fp + "\">" \
			+ relay_fp[0:8]
			+ "<br /><span class=\"tiny\">" \
			+ relay_fp
			+ "</span></td>\n")

		self.site.write("    <td>" \
		+ relay_nickname \
		+ " <br /><span class=\"agt\"><a href=\"https://atlas.torproject.org/#details/" \
		+ relay_fp + "\">Atlas</a> | " \
		+ "<a href=\"consensus-health-" \
		+ (self.get_consensus_time() - datetime.timedelta(hours=1)).strftime("%Y-%m-%d-%H-%M")
		+ ".html#" + relay_fp + "\">&#8668;</a></span>" \
		+ "</td>\n")

		relevantFlags = set()
		for dirauth_nickname in self.votes:
			if relay_fp in self.votes[dirauth_nickname].routers:
				relevantFlags.update(self.votes[dirauth_nickname].routers[relay_fp].flags)

		consensusFlags = set()
		if relay_fp in self.consensus.routers:
			consensusFlags = self.consensus.routers[relay_fp].flags
			relevantFlags.update(consensusFlags)

		relevantFlags = sorted(list(relevantFlags))
		for dirauth_nickname in self.votes:
			vote = self.votes[dirauth_nickname]
			if relay_fp in vote.routers:
				self.site.write("    <td>")
				
				flagsWritten = 0
				for flag in relevantFlags:
					self.site.write(" <br />" if flagsWritten > 0 else "")
					flagsWritten += 1

					if flag in vote.routers[relay_fp].flags:
						if not consensusFlags or flag in consensusFlags:
							self.site.write(flag)
						else:
							self.site.write("<span class=\"oiv\">" + flag + "</span>")
					elif consensusFlags and flag in vote.known_flags and flag in consensusFlags:
						self.site.write(  "<span class=\"oic\">" + flag + "</span>")
				
				if vote.routers[relay_fp].measured >= 0L:
					self.site.write(" <br />" if flagsWritten > 0 else "")
					self.site.write("bw=" + str(vote.routers[relay_fp].measured))
					flagsWritten += 1

				self.site.write("</td>\n");
			else:
				self.site.write("    <td></td>\n")

		if consensusFlags:
			self.site.write("    <td class=\"ic\">")
			flagsWritten = 0;
			
			for flag in relevantFlags:
				self.site.write(" <br />" if flagsWritten > 0 else "")
				flagsWritten += 1
		
				if flag in consensusFlags:
					self.site.write(flag)

			if self.consensus.routers[relay_fp].bandwidth >= 0L:
				self.site.write(" <br />" if flagsWritten > 0 else "")
				self.site.write("bw=" + str(self.consensus.routers[relay_fp].bandwidth))
				flagsWritten += 1

			if relay_fp in self.fallback_dirs:
				self.site.write(" <br />" if flagsWritten > 0 else "")
				self.site.write("FallbackDir")
				flagsWritten += 1

			self.site.write("</td>\n")
		else:
			self.site.write("    <td></td>\n")
		self.site.write("  </tr>\n")

	#-----------------------------------------------------------------------------------------
	def _write_page_footer(self):
		"""
		Write the footer of the HTML page containing the blurb that is on
		every page of the metrics website.
   		"""
		#XXX Write the git version and stem version the page was generated with
		self.site.write("</div>\n"
		+ "</div>\n"
		+ "<div class=\"bottom\" id=\"bottom\">\n"
		+ "<p>\"Tor\" and the \"Onion Logo\" are <a "
		+ "href=\"https://www.torproject.org/docs/trademark-faq.html.en\">"
		+ "registered trademarks</a> of The Tor Project, Inc.</p>\n"
		+ "</div>\n"
		+ "</body>\n"
		+ "</html>")

if __name__ == '__main__':
	"""
	I found that the most effective way to test this independently was to pickle the 
	downloaded conensuses in ./write_website.py like this:

	import pickle
	pickle.dump(consensuses, open('consensus.p', 'wb'))
	pickle.dump(votes, open('votes.p', 'wb'))

	Then I can run ./website.py and pdb.set_trace() where needed to debug
	"""
	import stem
	import pickle
	w = WebsiteWriter()

	c = pickle.load(open('consensus.p', 'rb'))
	w.set_consensuses(c)
	v = pickle.load(open('votes.p', 'rb'))
	w.set_votes(v)
	f = pickle.load(open('fallback_dirs.p', 'rb'))
	w.set_fallback_dirs(f)
		

	CONFIG = stem.util.conf.config_dict('consensus', {
                                    'known_params': [],
                                    'ignore_fallback_authorities': False,
                                    'graph_logical_min': 125,
                                    'graph_logical_max': 25000
                                    })
	config = stem.util.conf.get_config("consensus")
	config.load(os.path.join(os.path.dirname(__file__), 'data', 'consensus.cfg'))
	w.set_config(CONFIG)

	w.write_website(os.path.join(os.path.dirname(__file__), 'out', \
		'consensus-health-' + w.get_consensus_time().strftime("%Y-%m-%d-%H-%M") + '.html'), True)
	w.write_website(os.path.join(os.path.dirname(__file__), 'out', 'consensus-health.html'), True)
	w.write_website(os.path.join(os.path.dirname(__file__), 'out', 'index.html'), False)
