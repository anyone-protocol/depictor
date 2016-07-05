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

class GraphWriter:
	consensus = None
	votes = None
	known_authorities = []
	consensus_expirey = datetime.timedelta(hours=3)
	directory_key_warning_time = datetime.timedelta(days=14)
	known_params = []
	def write_website(self, filename):
		self.site = open(filename, 'w')
		self._write_page_header()
		self._write_valid_after_time()
		self._write_number_of_relays_voted_about()
		self._write_bandwidth_scanner_status()
		self._write_bandwidth_scanner_graphs()
		self._write_page_footer()
		self.site.close()

	def set_consensuses(self, c):
		self.consensuses = c
		self.consensus = max(c.itervalues(), key=operator.attrgetter('valid_after'))
		self.known_authorities = set([r.nickname for r in self.consensus.routers.values() if 'Authority' in r.flags and r.nickname != "Tonga"])
		self.known_authorities.update([r.nickname for r in self.consensus.directory_authorities])
		self.known_authorities.update([r for r in stem.descriptor.remote.get_authorities().keys() if r != "Tonga"])
	def set_votes(self, v):
		self.votes = v
	def set_consensus_expirey(self, timedelta):
		self.consensus_expirey = timedelta
	def set_directory_key_warning_time(self, timedelta):
		self.directory_key_warning_time = timedelta
	def set_config(self, config):
		self.known_params = config['known_params']
		self.bandwidth_authorities = config['bandwidth_authorities']
	def get_consensus_time(self):
		return self.consensus.valid_after

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
			+ "    <script src=\"https://d3js.org/d3.v4.0.0-alpha.4.min.js\"></script>\n"
			+ "    <script src=\"https://d3js.org/d3-dsv.v0.3.min.js\"></script>\n"
			+ "    <script src=\"https://cdnjs.cloudflare.com/ajax/libs/d3-legend/1.10.0/d3-legend.min.js\"></script>\n"
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
			+ "    .faravahar_bwauth {\n"
			+ "      fill: none;\n"
			+ "      stroke: steelblue;\n"
			+ "      background-color: steelblue;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .gabelmoo_bwauth {\n"
			+ "      fill: none;\n"
			+ "      stroke: orange;\n"
			+ "      background-color: orange;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .moria1_bwauth {\n"
			+ "      fill: none;\n"
			+ "      stroke: yellow;\n"
			+ "      background-color: yellow;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .maatuska_bwauth {\n"
			+ "      fill: none;\n"
			+ "      stroke: green;\n"
			+ "      background-color: green;\n"
			+ "      stroke-width: 1.5px;\n"
			+ "    }\n"
			+ "    .longclaw_bwauth {\n"
			+ "      fill: none;\n"
			+ "      stroke: red;\n"
			+ "      background-color: red;\n"
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

		if self.consensus.valid_after + self.consensus_expirey < datetime.datetime.now():
			self.site.write('<span class="oiv">'
			+ self.consensus.valid_after.isoformat().replace("T", " ")
			+ '</span>')
		else:
			self.site.write(self.consensus.valid_after.isoformat().replace("T", " "))

		self.site.write(". <i>Note that it takes up to 15 minutes to learn "
		+ "about new consensus and votes and process them.</i></p>\n")

	#-----------------------------------------------------------------------------------------
	def _write_number_of_relays_voted_about(self):
		"""
		Write the number of relays voted about.
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"numberofrelays\">\n"
		+ "<h3><a href=\"#numberofrelays\" class=\"anchor\">"
		+ "Number of relays voted about</a></h3>\n"
		+	 "<br>\n"
		+ "<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
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
	def _write_bandwidth_scanner_status(self):
		"""
		Write the status of bandwidth scanners and results being contained in votes.
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"bwauthstatus\">\n"
		+ "<h3><a href=\"#bwauthstatus\" class=\"anchor\">"
		+ "Bandwidth scanner status</a></h3>\n"
		+ "<br>\n"
		+ "<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
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
	def _write_bandwidth_scanner_graphs(self):
		"""
		Write the graphs of the bandwidth scanners
		"""
		self.site.write("<br>\n\n\n"
		+ " <!-- ================================================================= -->"
		+ "<a name=\"bwauthgraphs\">\n"
		+ "<h3><a href=\"#bwauthstatus\" class=\"anchor\">"
		+ "Bandwidth scanner graphs</a></h3>\n"
		+ "<br>\n"
		+ "<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" summary=\"\">\n"
		+ "  <colgroup>\n"
		+ "    <col width=\"160\">\n"
		+ "    <col width=\"640\">\n"
		+ "  </colgroup>\n"
		+ "  <tr>\n"
		+ "    <td>\n"
		+ "      <div id=\"graphspot\" style=\"text-align:center\">\n"
		+ "        <span class=\"moria1_bwauth\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> Moria\n"
		+ "        <span class=\"faravahar_bwauth\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> Faravahar\n"
		+ "        <span class=\"gabelmoo_bwauth\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> Gabelmoo\n"
		+ "        <span class=\"maatuska_bwauth\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> Maatuska\n"
		+ "        <span class=\"longclaw_bwauth\" style=\"margin-left:5px\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> Longclaw\n"
		+ "      </div>\n"
		+ "    </td>\n"
		+ "  </tr>\n"
		+ "</table>\n")

		s = """<script>
		var BWAUTH_LOGICAL_MIN = 125
		var BWAUTHS = ["faravahar_bwauth","gabelmoo_bwauth","moria1_bwauth","maatuska_bwauth","longclaw_bwauth"];
		var WIDTH = 800,
		    HEIGHT = 500,
			MARGIN = {top: 40, right: 40, bottom: 40, left: 40};

		var GRAPHS_TO_GENERATE = [
			{ title: "BWAuth Measured Relays, Past 30 Days", data_slice: 720 },
			{ title: "BWAuth Measured Relays, Past 90 Days", data_slice: 1000 },
			{ title: "BWAuth Measured Relays, Past Year", data_slice: 8760 },
			{ title: "BWAuth Measured Relays, Past 2 Years", data_slice: 17520 },
		];

		fetch("https://ritter.vg/misc/stuff/bwauth_data.txt").then(function(response) {
			return response.text();
		}).then(function(text) {
			return d3_dsv.csvParse(text);
		}).then(function(data) {

		// For each of the configured graphs
		for(g in GRAPHS_TO_GENERATE)
		{
			graph = GRAPHS_TO_GENERATE[g];

			if(data.length-graph.data_slice > 0)
				data_subset = data.slice(data.length-graph.data_slice);
			else
				data_subset = data

			// Calculate the Graph Boundaries -----------------------------------------
			min = 10000;
			max = 0;
			total = 0;
			count = 0;
			for(d in data_subset)
			{
				for(b in BWAUTHS)
				{
					data_subset[d][BWAUTHS[b]] = Number(data_subset[d][BWAUTHS[b]]);
					var x = data_subset[d][BWAUTHS[b]];
					if(x < min && x > BWAUTH_LOGICAL_MIN)
						min = x;
					if(x > max)
						max = x;	

					total += x;
					count++;
				}
			}
			avg = total / count;
			sumvariance = 0;
			for(d in data_subset)
			{
				for(b in BWAUTHS)
				{
					var x = data_subset[d][BWAUTHS[b]];
					sumvariance += (x - avg) * (x - avg);
				}
			}
			variance = sumvariance / count;
			stddev = Math.sqrt(variance);
			console.log("Data Length: " + data_subset.length + " Y-Axis Min: " + min + " Max: " + max + " Avg: " + avg + " Var: " + variance + " StdDev: " + stddev);

			// Create the Graph  -----------------------------------------
			var x = d3.scaleTime()
				.domain([new Date(Number(data_subset[0].date)), new Date(Number(data_subset[data_subset.length-1].date))])
			    .range([0, WIDTH])
			;

			var y = d3.scaleLinear()
				.domain([avg-(stddev), avg+(stddev)])
			    .range([HEIGHT, 0]);

			var lines = []
			for(bwauth in BWAUTHS)
			{
				this_bwauth = BWAUTHS[bwauth];
				lines.push({bwauth: this_bwauth, line: (function(tmp) {
					return d3.line()
					    .defined(function(d) { return d[tmp] && d[tmp] > BWAUTH_LOGICAL_MIN; })
			    		.x(function(d) { return x(new Date(Number(d.date))); })
				    	.y(function(d) { return y(d[tmp]); });
				    })(this_bwauth)});
			}

			var svg = d3.select("#graphspot").append("svg")
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
			    	.attr("class", lines[l].bwauth)
				    .attr("d", lines[l].line);
			}

			svg.append("text")
			        .attr("x", (WIDTH / 2))             
			        .attr("y", 0 - (MARGIN.top / 2))
			        .attr("text-anchor", "middle")  
			        .attr("class", "graph-title") 
			        .text(graph.title);
			}
		});

		</script>"""
		self.site.write(s)

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
