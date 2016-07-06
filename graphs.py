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
import stem.descriptor.remote
from base64 import b64decode

from website import WebsiteWriter
from parseOldConsensuses import get_dirauths_in_tables

class GraphWriter(WebsiteWriter):
	def write_website(self, filename):
		self.site = open(filename, 'w')
		self._write_page_header()
		self._write_valid_after_time()
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
			+ "    <script src=\"https://d3js.org/d3.v4.min.js\"></script>\n"
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
			+ "    .graphbox {\n"
			+ "      text-align: center;\n"
			+ "      display: none;\n"
			+ "    }\n"
			+ "    .faravahar {\n"
			+ "      fill: none;\n"
			+ "      stroke: steelblue;\n"
			+ "      background-color: steelblue;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .gabelmoo {\n"
			+ "      fill: none;\n"
			+ "      stroke: orange;\n"
			+ "      background-color: orange;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .moria1 {\n"
			+ "      fill: none;\n"
			+ "      stroke: yellow;\n"
			+ "      background-color: yellow;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .maatuska {\n"
			+ "      fill: none;\n"
			+ "      stroke: green;\n"
			+ "      background-color: green;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .longclaw {\n"
			+ "      fill: none;\n"
			+ "      stroke: red;\n"
			+ "      background-color: red;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .tor26 {\n"
			+ "      fill: none;\n"
			+ "      stroke: purple;\n"
			+ "      background-color: purple;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .urras {\n"
			+ "      fill: none;\n"
			+ "      stroke: black;\n"
			+ "      background-color: black;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .turtles {\n"
			+ "      fill: none;\n"
			+ "      stroke: #0000FF;\n"
			+ "      background-color: #0000FF;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .dizum {\n"
			+ "      fill: none;\n"
			+ "      stroke: limegreen;\n"
			+ "      background-color: limegreen;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .dannenberg {\n"
			+ "      fill: none;\n"
			+ "      stroke: pink;\n"
			+ "      background-color: pink;\n"
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
	def _write_number_of_relays_voted_about_graphs_spot(self, divName):
		self.site.write("  <tr>\n"
		+ "    <td>\n"
		+ "      <div id=\"" + str(divName) + "\" class=\"graphbox\">\n"
		+ "        <span class=\"moria1\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> Moria\n"
		+ "        <span class=\"faravahar\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> Faravahar\n"
		+ "        <span class=\"gabelmoo\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> Gabelmoo\n"
		+ "        <span class=\"maatuska\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> Maatuska\n"
		+ "        <span class=\"longclaw\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> Longclaw\n"
		+ "        <span class=\"tor26\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> tor26\n"
		+ "        <span class=\"dizum\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> dizum\n"
		+ "        <span class=\"dannenberg\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> dannenberg\n"
		+ "      </div>\n"
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
		+ "    <col width=\"160\">\n"
		+ "    <col width=\"640\">\n"
		+ "  </colgroup>\n"
		+ "  <tr class=\"graphplaceholder\">\n"
		+ "    <td>\n"
		+ "      <div style=\"text-align:center\">\n"
		+ "        Generating Graph... (requires SVG and Javascript support)\n"
		+ "      </div>\n"
		+ "    </td>\n"
		+ "  </tr>\n")
		self._write_number_of_relays_voted_about_graphs_spot("voted_total_1")
		self._write_number_of_relays_voted_about_graphs_spot("voted_total_2")
		self._write_number_of_relays_voted_about_graphs_spot("voted_total_3")
		self._write_number_of_relays_voted_about_graphs_spot("voted_total_4")
		self._write_number_of_relays_voted_about_graphs_spot("voted_running_1")
		self._write_number_of_relays_voted_about_graphs_spot("voted_running_2")
		self._write_number_of_relays_voted_about_graphs_spot("voted_running_3")
		self._write_number_of_relays_voted_about_graphs_spot("voted_running_4")
		self._write_number_of_relays_voted_about_graphs_spot("voted_notrunning_1")
		self._write_number_of_relays_voted_about_graphs_spot("voted_notrunning_2")
		self._write_number_of_relays_voted_about_graphs_spot("voted_notrunning_3")
		self._write_number_of_relays_voted_about_graphs_spot("voted_notrunning_4")
		self.site.write("</table>\n")

	#-----------------------------------------------------------------------------------------
	def _write_bandwidth_scanner_graphs_spot(self, divName):
		self.site.write("  <tr>\n"
		+ "    <td>\n"
		+ "      <div id=\"" + str(divName) + "\" class=\"graphbox\">\n"
		+ "        <span class=\"moria1\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> Moria\n"
		+ "        <span class=\"faravahar\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> Faravahar\n"
		+ "        <span class=\"gabelmoo\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> Gabelmoo\n"
		+ "        <span class=\"maatuska\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> Maatuska\n"
		+ "        <span class=\"longclaw\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> Longclaw\n"
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
		+ "    <col width=\"160\">\n"
		+ "    <col width=\"640\">\n"
		+ "  </colgroup>\n"
		+ "  <tr class=\"graphplaceholder\">\n"
		+ "    <td>\n"
		+ "      <div style=\"text-align:center\">\n"
		+ "        Generating Graph... (requires SVG and Javascript support)\n"
		+ "      </div>\n"
		+ "    </td>\n"
		+ "  </tr>\n")
		self._write_bandwidth_scanner_graphs_spot("bwauth_measured_1")
		self._write_bandwidth_scanner_graphs_spot("bwauth_measured_2")
		self._write_bandwidth_scanner_graphs_spot("bwauth_measured_3")
		self._write_bandwidth_scanner_graphs_spot("bwauth_measured_4")
		#self._write_bandwidth_scanner_graphs_spot("bwauth_running_unmeasured_1")
		#self._write_bandwidth_scanner_graphs_spot("bwauth_running_unmeasured_2")
		#self._write_bandwidth_scanner_graphs_spot("bwauth_running_unmeasured_3")
		#self._write_bandwidth_scanner_graphs_spot("bwauth_running_unmeasured_4")
		self.site.write("</table>\n")

	def _write_graph_javascript(self):
		s = """<script>
		var AUTH_LOGICAL_MIN = 125,
		    AUTH_LOGICAL_MAX = 25000;
		var WIDTH = 800,
		    HEIGHT = 500,
		    MARGIN = {top: 40, right: 40, bottom: 40, left: 40};

		var bwauths = ["faravahar","gabelmoo","moria1","maatuska","longclaw"];
		var dirauths = """ + str(get_dirauths_in_tables()) + """;
		dirauths.splice(dirauths.indexOf('urras'), 1);
		dirauths.splice(dirauths.indexOf('turtles'), 1);

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
				data_subset = data.slice(1);
				console.log("("+graph.title+") Requested " + (graph.data_slice+1) + " but there are only " + data.length + " items...");
			}
			else
				data_subset = data.slice(1, graph.data_slice+1);
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

			var lines = []
			for(auth in graph.authorities)
			{
				this_auth = graph.authorities[auth];
				lines.push({auth: this_auth, line: (function(dirAuthClosure) {
					return d3.line()
					    .defined(function(d) { 
						return d && graph.data_func(d, dirAuthClosure) && 
						graph.data_func(d, dirAuthClosure) > graph.min_ignore_limit &&
						graph.data_func(d, dirAuthClosure) < graph.max_ignore_limit; })
			    		.x(function(d) { return x(d.date); })
				    	.y(function(d) { return y(graph.data_func(d, dirAuthClosure)); });
				    })(this_auth)});
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
			    	.attr("class", lines[l].auth)
				    .attr("d", lines[l].line);
			}

			svg.append("text")
			        .attr("x", (WIDTH / 2))             
			        .attr("y", 0 - (MARGIN.top / 2))
			        .attr("text-anchor", "middle")  
			        .attr("class", "graph-title") 
			        .text(graph.title);
			}

			var toShow = document.getElementsByClassName('graphbox');
			for(i=0; i<toShow.length; i++) {
				console.log(toShow[i]);
				toShow[i].style.display = 'block';
			}
			var toHide = document.getElementsByClassName('graphplaceholder');
			for(i=0; i<toHide.length; i++) {
				console.log(toHide[i]);
				toHide[i].style.display = 'none';
			}
		});

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

	CONFIG = stem.util.conf.config_dict('consensus', {
                                    'ignored_authorities': [],
                                    'bandwidth_authorities': [],
                                    'known_params': [],
                                    })
	config = stem.util.conf.get_config("consensus")
	config.load(os.path.join(os.path.dirname(__file__), 'data', 'consensus.cfg'))
	g.set_config(CONFIG)

	g.write_website(os.path.join(os.path.dirname(__file__), 'out', 'graphs.html'))
