#!/usr/bin/env python3
# See LICENSE for licensing information

"""
Produces an HTML file for easily viewing voting and consensus differences
Ported from Java version Doctor
"""

import os
import time
import operator
import datetime
import stem.descriptor.remote
from base64 import b64decode

from website import WebsiteWriter
from utility import get_dirauths, get_bwauths

class GraphWriter(WebsiteWriter):
	def write_website(self, filename):
		self.site = open(filename, 'w')
		self._write_page_header()
		self._write_valid_after_time()
		self._write_fallback_directory_status(False)
		self._write_fallback_directory_status_graphs()
		self._write_number_of_relays_voted_about(False)
		self._write_number_of_relays_voted_about_graphs()
		self._write_bandwidth_scanner_status(False)
		self._write_bandwidth_scanner_graphs()
		self._write_graph_javascript()
		self._write_page_footer()
		self.site.close()

	#-----------------------------------------------------------------------------------------
	def _write_page_header(self):
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
			+ "    <script src=\"d3.v4.min.js\"></script>\n"
			+ "  </head>\n"
			+ "  <body>\n"
			+ "  <style>\n"
			+ "    svg {\n"
			+ "      font: 10px sans-serif;\n"
			+ "    }\n"
			+ "    .axis path,\n"
			+ "    .axis line {\n"
			+ "      fill: none;\n"
			+ "      stroke: #000;\n"
			+ "      shape-rendering: crispEdges;\n"
			+ "    }\n"
			+ "    .graph-title {\n"
			+ "    	font-size: 16px;\n"
			+ "    	text-decoration: underline;\n"
			+ "    }\n"
			+ "    .bwauth-graph-title {\n"
			+ "    	font-size: 12px;\n"
			+ "    	text-decoration: underline;\n"
			+ "    }\n"
			+ "    .graphbox {\n"
			+ "      text-align: center;\n"
			+ "      display: none;\n"
			+ "    }\n"
			+ "    .fallback_green {\n"
			+ "      fill: #1a9850;\n"
			+ "      stroke: #1a9850;\n"
			+ "      background-color: #1a9850;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .fallback_orange {\n"
			+ "      fill: #fdae61;\n"
			+ "      stroke: #fdae61;\n"
			+ "      background-color: #fdae61;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .fallback_red {\n"
			+ "      fill: #d73027;\n"
			+ "      stroke: #d73027;\n"
			+ "      background-color: #d73027;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .bwauth_above {\n"
			+ "      fill: #984ea3;\n"
			+ "      stroke: #984ea3;\n"
			+ "      background-color: #984ea3;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .bwauth_shared {\n"
			+ "      fill: #377eb8;\n"
			+ "      stroke: #377eb8;\n"
			+ "      background-color: #377eb8;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .bwauth_exclusive {\n"
			+ "      fill: #4daf4a;\n"
			+ "      stroke: #4daf4a;\n"
			+ "      background-color: #4daf4a;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .bwauth_below {\n"
			+ "      fill: #ff7f00;\n"
			+ "      stroke: #ff7f00;\n"
			+ "      background-color: #ff7f00;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .bwauth_unmeasured {\n"
			+ "      fill: #e41a1c;\n"
			+ "      stroke: #e41a1c;\n"
			+ "      background-color: #e41a1c;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .auth_moria1 {\n"
			+ "      stroke: #1f78b4 !important;\n"
			+ "      background-color: #1f78b4 !important;\n"
			+ "    }\n"
			+ "    .auth_tor26 {\n"
			+ "      stroke: #33a02c !important;\n"
			+ "      background-color: #33a02c !important;\n"
			+ "    }\n"
			+ "    .auth_dizum {\n"
			+ "      stroke: #e31a1c !important;\n"
			+ "      background-color: #e31a1c !important;\n"
			+ "    }\n"
			+ "    .auth_gabelmoo {\n"
			+ "      stroke: #ff7f00 !important;\n"
			+ "      background-color: #ff7f00 !important;\n"
			+ "    }\n"
			+ "    .auth_danneburg {\n"
			+ "      stroke: #6a3d9a !important;\n"
			+ "      background-color: #6a3d9a !important;\n"
			+ "    }\n"
			+ "    .auth_maatuska {\n"
			+ "      stroke: #a6cee3 !important;\n"
			+ "      background-color: #a6cee3 !important;\n"
			+ "    }\n"
			+ "    .auth_longclaw {\n"
			+ "      stroke: #b2df8a !important;\n"
			+ "      background-color: #b2df8a !important;\n"
			+ "    }\n"
			+ "    .auth_bastet {\n"
			+ "      stroke: #fb9a99 !important;\n"
			+ "      background-color: #fb9a99 !important;\n"
			+ "    }\n"
			+ "    .auth1 {\n"
			+ "      fill: none;\n"
			+ "      stroke: #1f78b4;\n"
			+ "      background-color: #1f78b4;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .auth2 {\n"
			+ "      fill: none;\n"
			+ "      stroke: #33a02c;\n"
			+ "      background-color: #33a02c;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .auth3 {\n"
			+ "      fill: none;\n"
			+ "      stroke: #e31a1c;\n"
			+ "      background-color: #e31a1c;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .auth4 {\n"
			+ "      fill: none;\n"
			+ "      stroke: #ff7f00;\n"
			+ "      background-color: #ff7f00;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .auth5 {\n"
			+ "      fill: none;\n"
			+ "      stroke: #6a3d9a;\n"
			+ "      background-color: #6a3d9a;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .auth6 {\n"
			+ "      fill: none;\n"
			+ "      stroke: #a6cee3;\n"
			+ "      background-color: #a6cee3;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .auth7 {\n"
			+ "      fill: none;\n"
			+ "      stroke: #b2df8a;\n"
			+ "      background-color: #b2df8a;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .auth8 {\n"
			+ "      fill: none;\n"
			+ "      stroke: #fb9a99;\n"
			+ "      background-color: #fb9a99;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .auth9 {\n"
			+ "      fill: none;\n"
			+ "      stroke: #fdbf6f;\n"
			+ "      background-color: #fdbf6f;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .auth10 {\n"
			+ "      fill: none;\n"
			+ "      stroke: #cab2d6;\n"
			+ "      background-color: #cab2d6;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .auth11 {\n"
			+ "      fill: none;\n"
			+ "      stroke: #ffff99;\n"
			+ "      background-color: #ffff99;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "  </style>\n"
			+ "    <div class=\"center\">\n"
			+ "      <div class=\"main-column\">\n"
			+ "        <h2>Consensus Health</h2>\n"
			+ "        <br>\n"
			+ "        <p>This page shows statistics about the current "
			+ "consensus and votes to facilitate debugging of the "
			+ "directory consensus process.")
		self.site.write("</p>\n")
		
	#-----------------------------------------------------------------------------------------
	def _write_fallback_directory_status_graphs_spot(self, divName):
		self.site.write("  <tr>\n"
		+ "    <td>\n"
		+ "      <div id=\"" + str(divName) + "\" class=\"graphbox\">\n"
        + "         <span class=\"fallback_green\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> Running\n"
        + "         <span class=\"fallback_orange\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> Not Running\n"
        + "         <span class=\"fallback_red\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> Missing From Consensus\n"
		+ "      </div>\n"
		+ "    </td>\n"
		+ "  </tr>\n")
	def _write_fallback_directory_status_graphs(self):
		"""
		Write the graphs of the fallback directory mirrors
		"""
		if self.config['ignore_fallback_authorities']:
			return

		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"fallbackdirgraphs\">\n"
		+ "<h3><a href=\"#fallbackdirgraphs\" class=\"anchor\">"
		+ "Fallback Directory graphs</a></h3>\n"
		+ "<br>\n"
		+ "<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
		+ "  <colgroup>\n"
		+ "    <col width=\"800\">\n"
		+ "  </colgroup>\n"
		+ "  <tr class=\"graphplaceholder\">\n"
		+ "    <td>\n"
		+ "      <div style=\"text-align:center\">\n"
		+ "        Generating Graph... (requires SVG and Javascript support)\n"
		+ "      </div>\n"
		+ "    </td>\n"
		+ "  </tr>\n")
		#self._write_fallback_directory_status_graphs_spot("fallbackdirs_pie")
		self._write_fallback_directory_status_graphs_spot("fallbackdirs_1")
		self._write_fallback_directory_status_graphs_spot("fallbackdirs_2")
		self._write_fallback_directory_status_graphs_spot("fallbackdirs_3")
		self._write_fallback_directory_status_graphs_spot("fallbackdirs_4")
		self.site.write("</table>\n")

	#-----------------------------------------------------------------------------------------
	def _write_number_of_relays_voted_about_graphs_spot(self, divName, dirAuths):
		self.site.write("  <tr>\n"
		+ "    <td>\n"
		+ "      <div id=\"" + str(divName) + "\" class=\"graphbox\">\n")

		i = 0
		for d in dirAuths:
			i += 1
			self.site.write("        <span class=\"auth_" + d + " auth" + str(i) + "\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> " + d + "\n")

		self.site.write("      </div>\n"
		+ "    </td>\n"
		+ "  </tr>\n")
	def _write_number_of_relays_voted_about_graphs(self):
		"""
		Write the graphs of the number of relays voted about
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"votedaboutgraphs\">\n"
		+ "<h3><a href=\"#votedaboutgraphs\" class=\"anchor\">"
		+ "Number of relays voted about graphs</a></h3>\n"
		+ "<br>\n"
		+ "<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
		+ "  <colgroup>\n"
		+ "    <col width=\"800\">\n"
		+ "  </colgroup>\n"
		+ "  <tr class=\"graphplaceholder\">\n"
		+ "    <td>\n"
		+ "      <div style=\"text-align:center\">\n"
		+ "        Generating Graph... (requires SVG and Javascript support)\n"
		+ "      </div>\n"
		+ "    </td>\n"
		+ "  </tr>\n")
		self._write_number_of_relays_voted_about_graphs_spot("voted_total_1", get_dirauths())
		self._write_number_of_relays_voted_about_graphs_spot("voted_total_2", get_dirauths())
		self._write_number_of_relays_voted_about_graphs_spot("voted_total_3", get_dirauths())
		self._write_number_of_relays_voted_about_graphs_spot("voted_total_4", get_dirauths())
		self._write_number_of_relays_voted_about_graphs_spot("voted_running_1", get_dirauths())
		self._write_number_of_relays_voted_about_graphs_spot("voted_running_2", get_dirauths())
		self._write_number_of_relays_voted_about_graphs_spot("voted_running_3", get_dirauths())
		self._write_number_of_relays_voted_about_graphs_spot("voted_running_4", get_dirauths())
		self._write_number_of_relays_voted_about_graphs_spot("voted_notrunning_1", get_dirauths())
		self._write_number_of_relays_voted_about_graphs_spot("voted_notrunning_2", get_dirauths())
		self._write_number_of_relays_voted_about_graphs_spot("voted_notrunning_3", get_dirauths())
		self._write_number_of_relays_voted_about_graphs_spot("voted_notrunning_4", get_dirauths())
		self.site.write("</table>\n")

	#-----------------------------------------------------------------------------------------
	def _write_bandwidth_scanner_graphs_spot(self, divName, bwAuths):
		self.site.write("  <tr>\n"
		+ "    <td>\n"
		+ "      <div id=\"" + str(divName) + "\" class=\"graphbox\">\n")

		i = 0
		for d in bwAuths:
			i += 1
			self.site.write("        <span class=\"auth_" + d + " auth" + str(i) + "\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> " + d + "\n")

		self.site.write("      </div>\n"
		+ "    </td>\n"
		+ "  </tr>\n")
	def _write_bandwidth_scanner_statistics_graphs_spot(self, divName, timeframe):
		self.site.write("  <tr>\n"
		+ "    <td>\n"
		+ "      <div id=\"" + str(divName) + "\" class=\"graphbox\">\n"
        + "         <span class=\"graph-title\">Bandwidth Auth Statistics, Past " + timeframe + " Days</span>\n"
        + "         <br />\n"
        + "         <span class=\"bwauth_above\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> above consensus\n"
        + "         <span class=\"bwauth_shared\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> shared\n"
        + "         <span class=\"bwauth_exclusive\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> exclusive\n"
        + "         <span class=\"bwauth_below\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> below consensus\n"
        + "         <span class=\"bwauth_unmeasured\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> unmeasured\n"
		+ "      </div>\n"
		+ "    </td>\n"
		+ "  </tr>\n")
	def _write_bandwidth_scanner_graphs(self):
		"""
		Write the graphs of the bandwidth scanners
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"bwauthgraphs\">\n"
		+ "<h3><a href=\"#bwauthgraphs\" class=\"anchor\">"
		+ "Bandwidth scanner measured relays</a></h3>\n"
		+ "<br>\n"
		+ "<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
		+ "  <colgroup>\n"
		+ "    <col width=\"800\">\n"
		+ "  </colgroup>\n"
		+ "  <tr class=\"graphplaceholder\">\n"
		+ "    <td>\n"
		+ "      <div style=\"text-align:center\">\n"
		+ "        Generating Graph... (requires SVG and Javascript support)\n"
		+ "      </div>\n"
		+ "    </td>\n"
		+ "  </tr>\n")
		self._write_bandwidth_scanner_graphs_spot("bwauth_measured_1", get_bwauths())
		self._write_bandwidth_scanner_graphs_spot("bwauth_measured_2", get_bwauths())
		self._write_bandwidth_scanner_graphs_spot("bwauth_measured_3", get_bwauths())
		self._write_bandwidth_scanner_graphs_spot("bwauth_measured_4", get_bwauths())
		self._write_bandwidth_scanner_statistics_graphs_spot("bwauths_stats_1", "7")
		self._write_bandwidth_scanner_statistics_graphs_spot("bwauths_stats_2", "14")
		self._write_bandwidth_scanner_statistics_graphs_spot("bwauths_stats_3", "30")
		self._write_bandwidth_scanner_statistics_graphs_spot("bwauths_stats_4", "90")
		#self._write_bandwidth_scanner_graphs_spot("bwauth_running_unmeasured_1")
		#self._write_bandwidth_scanner_graphs_spot("bwauth_running_unmeasured_2")
		#self._write_bandwidth_scanner_graphs_spot("bwauth_running_unmeasured_3")
		#self._write_bandwidth_scanner_graphs_spot("bwauth_running_unmeasured_4")
		self.site.write("</table>\n")

	def _write_graph_javascript(self):
		s = """<script>
		var AUTH_LOGICAL_MIN = """ + str(self.config['graph_logical_min']) + """,
		    AUTH_LOGICAL_MAX = """ + str(self.config['graph_logical_max']) + """;
		var WIDTH = 800,  BWAUTH_WIDTH = 800,
		    HEIGHT = 500, BWAUTH_HEIGHT = 200,
		    MARGIN = {top: 40, right: 40, bottom: 40, left: 40},
		    BWAUTH_MARGIN = {top: 14, right: 40, bottom: 20, left: 40};
		
		

		var bwauths = """ + str(list(get_bwauths().keys())) + """;
		var dirauths = """ + str(list(get_dirauths().keys())) + """;
		var ignore_fallback_dirs = """ + str(self.config['ignore_fallback_authorities']).lower() + """;

		var _getBandwidthDataValue = function(d, dirauth) { return d[dirauth + "_bwauth"]; }
		var _getRunningDataValue = function(d, dirauth) { return d[dirauth + "_running"]; }
		var _getTotalDataValue =  function(d, dirauth) { return d[dirauth + "_known"]; }
		var _getNonRunningDataValue = function(d, dirauth) { return d[dirauth + "_known"] - d[dirauth + "_running"]; }
		var _getRunningUnmeasuredDataValue = function(d, dirauth) { return d[dirauth + "_running"] - d[dirauth + "_bwauth"]; }

		var GRAPHS_TO_GENERATE = [
			{ title: "Voted About Relays (Running), Past 7 Days", data_slice: 168, div: "voted_running_1", 
				data_func: _getRunningDataValue, authorities: dirauths, min_ignore_limit:AUTH_LOGICAL_MIN, max_ignore_limit:AUTH_LOGICAL_MAX },
			{ title: "Voted About Relays (Running), Past 14 Days", data_slice: 336, div: "voted_running_2", 
				data_func: _getRunningDataValue, authorities: dirauths, min_ignore_limit:AUTH_LOGICAL_MIN, max_ignore_limit:AUTH_LOGICAL_MAX },
			{ title: "Voted About Relays (Running), Past 30 Days", data_slice: 720, div: "voted_running_3", 
				data_func: _getRunningDataValue, authorities: dirauths, min_ignore_limit:AUTH_LOGICAL_MIN, max_ignore_limit:AUTH_LOGICAL_MAX },
			{ title: "Voted About Relays (Running), Past 90 Days", data_slice: 2160, div: "voted_running_4", 
				data_func: _getRunningDataValue, authorities: dirauths, min_ignore_limit:AUTH_LOGICAL_MIN, max_ignore_limit:AUTH_LOGICAL_MAX },

			{ title: "Voted About Relays (Total), Past 7 Days", data_slice: 168, div: "voted_total_1", 
				data_func: _getTotalDataValue, authorities: dirauths, min_ignore_limit:AUTH_LOGICAL_MIN, max_ignore_limit:AUTH_LOGICAL_MAX },
			{ title: "Voted About Relays (Total), Past 14 Days", data_slice: 336, div: "voted_total_2", 
				data_func: _getTotalDataValue, authorities: dirauths, min_ignore_limit:AUTH_LOGICAL_MIN, max_ignore_limit:AUTH_LOGICAL_MAX },
			{ title: "Voted About Relays (Total), Past 30 Days", data_slice: 720, div: "voted_total_3", 
				data_func: _getTotalDataValue, authorities: dirauths, min_ignore_limit:AUTH_LOGICAL_MIN, max_ignore_limit:AUTH_LOGICAL_MAX },
			{ title: "Voted About Relays (Total), Past 90 Days", data_slice: 2160, div: "voted_total_4", 
				data_func: _getTotalDataValue, authorities: dirauths, min_ignore_limit:AUTH_LOGICAL_MIN, max_ignore_limit:AUTH_LOGICAL_MAX },

			{ title: "Voted About Relays (Not Running), Past 7 Days", data_slice: 168, div: "voted_notrunning_1", 
				data_func: _getNonRunningDataValue, authorities: dirauths, min_ignore_limit:0, max_ignore_limit:4000 },
			{ title: "Voted About Relays (Not Running), Past 14 Days", data_slice: 336, div: "voted_notrunning_2", 
				data_func: _getNonRunningDataValue, authorities: dirauths, min_ignore_limit:0, max_ignore_limit:4000 },
			{ title: "Voted About Relays (Not Running), Past 30 Days", data_slice: 720, div: "voted_notrunning_3", 
				data_func: _getNonRunningDataValue, authorities: dirauths, min_ignore_limit:0, max_ignore_limit:4000 },
			{ title: "Voted About Relays (Not Running), Past 90 Days", data_slice: 2160, div: "voted_notrunning_4", 
				data_func: _getNonRunningDataValue, authorities: dirauths, min_ignore_limit:0, max_ignore_limit:4000 },

			{ title: "BWAuth Measured Relays, Past 7 Days", data_slice: 168, div: "bwauth_measured_1", 
				data_func: _getBandwidthDataValue, authorities: bwauths, min_ignore_limit:AUTH_LOGICAL_MIN, max_ignore_limit:AUTH_LOGICAL_MAX },
			{ title: "BWAuth Measured Relays, Past 14 Days", data_slice: 336, div: "bwauth_measured_2", 
				data_func: _getBandwidthDataValue, authorities: bwauths, min_ignore_limit:AUTH_LOGICAL_MIN, max_ignore_limit:AUTH_LOGICAL_MAX },
			{ title: "BWAuth Measured Relays, Past 30 Days", data_slice: 720, div: "bwauth_measured_3", 
				data_func: _getBandwidthDataValue, authorities: bwauths, min_ignore_limit:AUTH_LOGICAL_MIN, max_ignore_limit:AUTH_LOGICAL_MAX },
			{ title: "BWAuth Measured Relays, Past 90 Days", data_slice: 2160, div: "bwauth_measured_4", 
				data_func: _getBandwidthDataValue, authorities: bwauths, min_ignore_limit:AUTH_LOGICAL_MIN, max_ignore_limit:AUTH_LOGICAL_MAX },

			/* These graphs are very misleading and not helpful
			{ title: "BWAuth Running Unmeasured Relays, Past 30 Days", data_slice: 720, div: "bwauth_running_unmeasured_1", 
				data_func: _getRunningUnmeasuredDataValue, authorities: bwauths, min_ignore_limit:-1000, max_ignore_limit:AUTH_LOGICAL_MAX },
			{ title: "BWAuth Running Unmeasured Relays, Past 90 Days", data_slice: 2160, div: "bwauth_running_unmeasured_2", 
				data_func: _getRunningUnmeasuredDataValue, authorities: bwauths, min_ignore_limit:-1000, max_ignore_limit:AUTH_LOGICAL_MAX },
			{ title: "BWAuth Running Unmeasured Relays, Past Year", data_slice: 8760, div: "bwauth_running_unmeasured_3", 
				data_func: _getRunningUnmeasuredDataValue, authorities: bwauths, min_ignore_limit:-1000, max_ignore_limit:AUTH_LOGICAL_MAX },
			{ title: "BWAuth Running Unmeasured Relays, Past 2 Years", data_slice: 17520, div: "bwauth_running_unmeasured_4", 
				data_func: _getRunningUnmeasuredDataValue, authorities: bwauths, min_ignore_limit:-1000, max_ignore_limit:AUTH_LOGICAL_MAX },
			*/
		];

		var FALLBACK_GRAPHS_TO_GENERATE = [
			{ title: "Fallback Directories Running, Past 7 Days", data_slice: 168, div: "fallbackdirs_1", 
				data_func: null, authorities: dirauths, min_ignore_limit:null, max_ignore_limit:null },
			{ title: "Fallback Directories Running, Past 14 Days", data_slice: 336, div: "fallbackdirs_2", 
				data_func: null, authorities: dirauths, min_ignore_limit:null, max_ignore_limit:null },
			{ title: "Fallback Directories Running, Past 30 Days", data_slice: 720, div: "fallbackdirs_3", 
				data_func: null, authorities: dirauths, min_ignore_limit:null, max_ignore_limit:null },
			{ title: "Fallback Directories Running, Past 90 Days", data_slice: 2160, div: "fallbackdirs_4", 
				data_func: null, authorities: dirauths, min_ignore_limit:null, max_ignore_limit:null },
		];

		var BWAUTH_GRAPHS_TO_GENERATE = [
			{ title: "Bandwidth Auth Statistics, Past 7 Days", data_slice: 168, div: "bwauths_stats_1", 
				data_func: null, authorities: bwauths, min_ignore_limit:null, max_ignore_limit:null },
			{ title: "Bandwidth Auth Statistics, Past 14 Days", data_slice: 336, div: "bwauths_stats_2", 
				data_func: null, authorities: bwauths, min_ignore_limit:null, max_ignore_limit:null },
			{ title: "Bandwidth Auth Statistics, Past 30 Days", data_slice: 720, div: "bwauths_stats_3", 
				data_func: null, authorities: bwauths, min_ignore_limit:null, max_ignore_limit:null },
			{ title: "Bandwidth Auth Statistics, Past 90 Days", data_slice: 2160, div: "bwauths_stats_4", 
				data_func: null, authorities: bwauths, min_ignore_limit:null, max_ignore_limit:null },
		];

	    relays_done = false;
	    fallbackdirs_done = ignore_fallback_dirs;
	    bwauth_done = false;
		fetch("vote-stats.csv").then(function(response) {
			return response.text();
		}).then(function(text) {
			return d3.csvParse(text, function(d) {
				for(i in d) {
					if(i == "date")
						d[i] = new Date(Number(d[i]));
					else
						d[i] = Number(d[i]);
				}
				return d;
			});
		}).then(function(data) {

		// For each of the configured graphs
		for(g in GRAPHS_TO_GENERATE)
		{
			graph = GRAPHS_TO_GENERATE[g];

			if(graph.data_slice+1 > data.length) {
				data_subset = data.slice(0);
				console.log("("+graph.title+") Requested " + (graph.data_slice+1) + " but there are only " + data.length + " items...");
			}
			else
				data_subset = data.slice(0, graph.data_slice+1);
			data_subset.reverse();

			// Calculate the Graph Boundaries -----------------------------------------
			min = 10000;
			max = 0;
			total = 0;
			count = 0;
			for(d in data_subset)
			{
				for(a in graph.authorities)
				{
					var x = graph.data_func(data_subset[d], graph.authorities[a]);
					if(isNaN(x))
						console.log("Error, NAN:", data_subset[d], graph.authorities[a], x);
					if(x < min && x > graph.min_ignore_limit)
						min = x;
					if(x > max && x < graph.max_ignore_limit)
						max = x;
					if(x > graph.min_ignore_limit && x < graph.max_ignore_limit) {
						total += x;
						count++;
					}
				}
			}
			avg = total / count;
			sumvariance = 0;
			for(d in data_subset)
			{
				for(a in graph.authorities)
				{
					var x = graph.data_func(data_subset[d], graph.authorities[a]);
					if(x > graph.min_ignore_limit && x < graph.max_ignore_limit) {
						sumvariance += (x - avg) * (x - avg);
					}
				}
			}
			variance = sumvariance / count;
			stddev = Math.sqrt(variance);
			console.log("("+graph.title+") Data Length: " + data_subset.length + " Y-Axis Min: " + min + " Max: " + max + " Avg: " + avg + " Var: " + variance + " StdDev: " + stddev);

			// Create the Graph  -----------------------------------------
			var x = d3.scaleTime()
				.domain([data_subset[0].date, data_subset[data_subset.length-1].date])
			    .range([0, WIDTH])
			;

			var y = d3.scaleLinear()
				.domain([avg-(5*stddev), avg+(5*stddev)])
			    .range([HEIGHT, 0]);

			var i = 1;
			var lines = []
			for(auth in graph.authorities)
			{
				this_auth = graph.authorities[auth];
				lines.push({authName: this_auth, authIndex: i, line: (function(dirAuthClosure) {
					return d3.line()
					    .defined(function(d) { 
						return d && graph.data_func(d, dirAuthClosure) && 
						graph.data_func(d, dirAuthClosure) > graph.min_ignore_limit &&
						graph.data_func(d, dirAuthClosure) < graph.max_ignore_limit; })
			    		.x(function(d) { return x(d.date); })
				    	.y(function(d) { return y(graph.data_func(d, dirAuthClosure)); });
				    })(this_auth)});
			    i++;
			}

			var svg = d3.select("#" + graph.div).append("svg")
			    .datum(data_subset)
			    .attr("width", WIDTH + MARGIN.left + MARGIN.right)
			    .attr("height", HEIGHT + MARGIN.top + MARGIN.bottom)
			    .append("g")
			    .attr("transform", "translate(" + MARGIN.left + "," + MARGIN.top + ")");

			svg.append("g")
			    .attr("class", "axis axis--x")
			    .attr("transform", "translate(0," + HEIGHT + ")")
			    .call(d3.axisBottom().scale(x));

			svg.append("g")
			    .attr("class", "axis axis--y")
			    .call(d3.axisLeft().scale(y));

			for(l in lines)
			{
				svg.append("path")
			    	.attr("class", "auth_" + lines[l].authName + " auth" + lines[l].authIndex)
				    .attr("d", lines[l].line);
			}

			svg.append("text")
			        .attr("x", (WIDTH / 2))
			        .attr("y", 0 - (MARGIN.top / 2))
			        .attr("text-anchor", "middle")
			        .attr("class", "graph-title")
			        .text(graph.title);
		}

		relays_done = true;
		if(fallbackdirs_done && bwauth_done) {
			var toShow = document.getElementsByClassName('graphbox');
			for(i=0; i<toShow.length; i++) {
				toShow[i].style.display = 'block';
			}
			var toHide = document.getElementsByClassName('graphplaceholder');
			for(i=0; i<toHide.length; i++) {
				toHide[i].style.display = 'none';
			}
		}

		});

		// ===========================================================================================
		// ===========================================================================================

		fetch("bwauth-stats.csv").then(function(response) {
			return response.text();
		}).then(function(text) {
			return d3.csvParse(text, function(d) {
				for(i in d) {
					if(i == "date")
						d[i] = new Date(Number(d[i]));
					else
						d[i] = Number(d[i]);
				}
				return d;
			});
		}).then(function(data) {
			for(g in BWAUTH_GRAPHS_TO_GENERATE)
			{
				graph = BWAUTH_GRAPHS_TO_GENERATE[g];

				var key_to_color = function(k) { 
					if(k.includes("_above"))
						return "bwauth_above";
					else if(k.includes("_shared"))
						return "bwauth_shared";
					else if(k.includes("_exclusive"))
						return "bwauth_exclusive";
					else if(k.includes("_below"))
						return "bwauth_below";
					else
						return "bwauth_unmeasured";
				};

				if(graph.data_slice+1 > data.length) {
					data_subset = data.slice(0);
					console.log("("+graph.title+") Requested " + (graph.data_slice+1) + " but there are only " + data.length + " items...");
				}
				else
					data_subset = data.slice(0, graph.data_slice);
				data_subset.reverse();

				for(a in graph.authorities)
				{
					a = graph.authorities[a];

					max = 0;
					for(d in data_subset)
					{
						x = data_subset[d][a + "_above"] +
							data_subset[d][a + "_shared"] +
							data_subset[d][a + "_exclusive"] +
							data_subset[d][a + "_below"] +
							data_subset[d][a + "_unmeasured"];
						if(x > max)
							max = x;
					}

					var x = d3.scaleTime()
						.domain([data_subset[0].date, data_subset[data_subset.length-1].date])
						.range([0, BWAUTH_WIDTH]);

					var y = d3.scaleLinear()
						.domain([0, max])
						.range([BWAUTH_HEIGHT, 0]);

					var stack = d3.stack()
						.keys([a + "_unmeasured", a + "_below", a + "_exclusive", a + "_shared", a + "_above"])
						.order(d3.stackOrderNone)
						.offset(d3.stackOffsetNone);

					var area = d3.area()
						.x(function(d, i) { return x(d.data.date); })
						.y0(function(d) { return y(d[0]); })
						.y1(function(d) { return y(d[1]); });

					var svg = d3.select("#" + graph.div).append("svg")
						.attr("width", BWAUTH_WIDTH + BWAUTH_MARGIN.left + BWAUTH_MARGIN.right)
						.attr("height", BWAUTH_HEIGHT + BWAUTH_MARGIN.top + BWAUTH_MARGIN.bottom)
						.append("g")
						.attr("transform", "translate(" + BWAUTH_MARGIN.left + "," + BWAUTH_MARGIN.top + ")");

					var layer = svg.selectAll(".layer")
						.data(stack(data_subset))
						.enter().append("g")
						//.attr("class", "layer");

					layer.append("path")
						//.attr("class", "area")
						.attr("class", function(d) { return key_to_color(d.key); })
						.attr("d", area);

					svg.append("g")
						.attr("class", "axis axis--x")
						.attr("transform", "translate(0," + BWAUTH_HEIGHT + ")")
						.call(d3.axisBottom().scale(x));

					svg.append("g")
						.attr("class", "axis axis--y")
						.call(d3.axisLeft().scale(y));

					svg.append("text")
						.attr("x", (BWAUTH_WIDTH / 2))
						.attr("y", 5 - (BWAUTH_MARGIN.top / 2))
						.attr("text-anchor", "middle")
						.attr("class", "bwauth-graph-title")
						.text(a);
					}
				}


				bwauth_done = true;
				if(relays_done && fallbackdirs_done) {
					var toShow = document.getElementsByClassName('graphbox');
					for(i=0; i<toShow.length; i++) {
						toShow[i].style.display = 'block';
					}
					var toHide = document.getElementsByClassName('graphplaceholder');
					for(i=0; i<toHide.length; i++) {
						toHide[i].style.display = 'none';
					}
				}
		});

		// ===========================================================================================
		// ===========================================================================================

		if(!ignore_fallback_dirs) {

			fetch("fallback-dir-stats.csv").then(function(response) {
				return response.text();
			}).then(function(text) {
				return d3.csvParse(text, function(d) {
					for(i in d) {
						if(i == "date")
							d[i] = new Date(Number(d[i]));
						else
							d[i] = Number(d[i]);
					}
					return d;
				});
			}).then(function(data) {
				var key_to_color = function(k) { return k == 'fallback_dirs_running' ? 'fallback_green' : k == 'fallback_dirs_notrunning' ? 'fallback_orange' : 'fallback_red' };
				/*Pie Graph
				data_subset = data.slice(0);
				data_subset = [
					{'label' : 'fallback_dirs_running', 'value': data_subset[0]['fallback_dirs_running']},
					{'label' : 'fallback_dirs_notrunning', 'value': data_subset[0]['fallback_dirs_notrunning']},
					{'label' : 'fallback_dirs_missing', 'value': data_subset[0]['fallback_dirs_missing']},
				];
				var data_func = function(d) { return d.value; };
				var arcs = d3.pie()
					.sort(null)
					.value(data_func)(data_subset);

				var svg = d3.select('#fallbackdirs_pie')
					.append('svg')
					.attr('width', WIDTH)
					.attr('height', HEIGHT)
					.append('g')
					.attr('transform', 'translate(' + (WIDTH / 2) +	',' + (HEIGHT / 2) + ')');

				var arc = d3.arc()
					.innerRadius(0)
					.outerRadius(100);

				var path = svg.selectAll('path')
					.data(arcs)
					.enter()
					.append('path')
					.attr('d', arc)
					.attr('class', function(d, i) {
						return key_to_color(d.data.label);
					});*/

				//Line Graphs
				for(g in FALLBACK_GRAPHS_TO_GENERATE)
				{
					graph = FALLBACK_GRAPHS_TO_GENERATE[g];

					if(graph.data_slice+1 > data.length) {
						data_subset = data.slice(0);
						console.log("("+graph.title+") Requested " + (graph.data_slice+1) + " but there are only " + data.length + " items...");
					}
					else
						data_subset = data.slice(0, graph.data_slice);
					data_subset.reverse();
				
					max = 0
					for(d in data_subset) {
						x = data_subset[d]['fallback_dirs_running'] + data_subset[d]['fallback_dirs_notrunning'] + data_subset[d]['fallback_dirs_missing'];
						if(x > max)
							max = x;
					}

					var x = d3.scaleTime()
						.domain([data_subset[0].date, data_subset[data_subset.length-1].date])
						.range([0, WIDTH]);

					var y = d3.scaleLinear()
						.domain([0, max])
						.range([HEIGHT, 0]);

					var stack = d3.stack()
						.keys(["fallback_dirs_missing", "fallback_dirs_notrunning", "fallback_dirs_running"])
						.order(d3.stackOrderNone)
						.offset(d3.stackOffsetNone);

					var area = d3.area()
						.x(function(d, i) { return x(d.data.date); })
						.y0(function(d) { return y(d[0]); })
						.y1(function(d) { return y(d[1]); });

					var svg = d3.select("#" + graph.div).append("svg")
						.attr("width", WIDTH + MARGIN.left + MARGIN.right)
						.attr("height", HEIGHT + MARGIN.top + MARGIN.bottom)
						.append("g")
						.attr("transform", "translate(" + MARGIN.left + "," + MARGIN.top + ")");

					var layer = svg.selectAll(".layer")
						.data(stack(data_subset))
						.enter().append("g")
						//.attr("class", "layer");

					layer.append("path")
						//.attr("class", "area")
						.attr("class", function(d) { return key_to_color(d.key); })
						.attr("d", area);

					svg.append("g")
						.attr("class", "axis axis--x")
						.attr("transform", "translate(0," + HEIGHT + ")")
						.call(d3.axisBottom().scale(x));

					svg.append("g")
						.attr("class", "axis axis--y")
						.call(d3.axisLeft().scale(y));

					svg.append("text")
						.attr("x", (WIDTH / 2))
						.attr("y", 0 - (MARGIN.top / 2))
						.attr("text-anchor", "middle")
						.attr("class", "graph-title")
						.text(graph.title);
				}

				
				fallbackdirs_done = true;
				if(relays_done && bwauth_done) {
					var toShow = document.getElementsByClassName('graphbox');
					for(i=0; i<toShow.length; i++) {
						toShow[i].style.display = 'block';
					}
					var toHide = document.getElementsByClassName('graphplaceholder');
					for(i=0; i<toHide.length; i++) {
						toHide[i].style.display = 'none';
					}
				}
			});
		}

		</script>"""
		self.site.write(s)

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
	g = GraphWriter()

	c = pickle.load(open('consensus.p', 'rb'))
	g.set_consensuses(c)
	v = pickle.load(open('votes.p', 'rb'))
	g.set_votes(v)
	f = pickle.load(open('fallback_dirs.p', 'rb'))
	g.set_fallback_dirs(f)


	CONFIG = stem.util.conf.config_dict('consensus', {
                                    'ignore_fallback_authorities': False,
                                    'graph_logical_min': 125,
                                    'graph_logical_max': 25000
                                    })
	config = stem.util.conf.get_config("consensus")
	config.load(os.path.join(os.path.dirname(__file__), 'data', 'consensus.cfg'))
	g.set_config(CONFIG)
	g.write_website(os.path.join(os.path.dirname(__file__), 'out', 'graphs.html'))