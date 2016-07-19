#!/usr/bin/python

from datetime import datetime,timedelta
from elasticsearch import Elasticsearch
import json
import time
import itertools
from collections import OrderedDict
import subprocess
import smtplib
test ={}

server = smtplib.SMTP('smtp.gmail.com', 587)
server.ehlo()
server.starttls()
#Next, log in to the server
server.login("msft-alerts-ext@arista.com","lsgipeqsjpdhsjiu")
fromAddr = "msft-alerts-ext@arista.com"
toAddr = ["wasst@microsoft.com","msft-team@arista.com"]
#toAddr = ["urvish@arista.com"]
emailSubject = "Daily Automated SYSLOG Report"

# Create Log report file
fileName = "DailyReport-" + str(time.strftime('%Y%m%d'))


es = Elasticsearch(timeout=600)
severity = [0,0,0,0,0,0,0]
programs = {}
hosts = {}
hosts_IPT = {}
hosto_Parity = {}

# List of errors that we are interested in
errorStrings = ["%CAPACITY-1-UTILIZATION_HIGH",
                "%ROUTING-3-HW_RESOURCE_FULL",
		"%SAND-3-DDR_BIST_FAILED",
		"%IP6ROUTING-3-HW_RESOURCE_FULL",
		"%SAND-3-ROUTING_LEM_RESOURCE_FULL",
		"%SAND-3-INTERRUPT_OCCURRED",
		"%HARDWARE-3-ERROR_DETECTED",
                "%HARDWARE-3-DROP_COUNTER",
		"%HARDWARE-3-FPGA_PROGRAMMER_ERROR",
		"%HARDWARE-3-FPGA_CONFIG_ERROR",
                "%BGP-5-IF-MAXROUTESWARNING",
#                "PFC_WATCHDOG",
                "%SAND-4-FABRICSERDES_LINK_FAILED",
                "%PROGMGR-3-PROCESS_DELAYRESTART",
		"%PROCMGR-6-PROCESS_RESTART"
		]
changeSeverity = {"%SAND-3-INTERRUPT_OCCURRED":2,
		"%HARDWARE-3-ERROR_DETECTED":2,
		"%HARDWARE-3-DROP_COUNTER":2,
		"%BGP-5-IF-MAXROUTESWARNING":2,
		"%ROUTING-3-HW_RESOURCE_FULL":2,
		"%IP6ROUTING-3-HW_RESOURCE_FULL":2,
		"%SAND-3-ROUTING_LEM_RESOURCE_FULL":2}

today = datetime.utcnow().date()


# Start time for the query. Time in miliseconds since epoch. This is usually the time when the day started
startTime = int(datetime(today.year, today.month, today.day).strftime('%s'))*1000 
#startTime = 1459321200000
#print startTime


endTime = int((datetime(today.year, today.month, today.day) + timedelta(1)).strftime('%s'))*1000 -1 
# End time for the query. This is the time when the query is ran i.e current time.
#endTime = 1459407599999
#print endTime


# filter for the query
#query = "ar_severity: [0 TO 3] NOT (program: Rib OR program: Thermostat)"
query = "ar_severity: [0 TO 6] NOT (program: Lag+LacpAgent OR program: Rib OR program: Thermostat OR program: Lldp OR program: Cli OR program: Ucd9012 OR program: PFC_WATCHDOG)"

#for error in errorStrings:
#	query += ' OR \\"' + error + '\\"'

#print query
#query = "*"

indices = "logstash-*"

# Search the elasticsearch db.
res = es.search(index=indices,body={
  "highlight": {
    "pre_tags": [
      "@kibana-highlighted-field@"
    ],
    "post_tags": [
      "@/kibana-highlighted-field@"
    ],
    "fields": {
      "*": {}
    },
    "fragment_size": 2147483647
  },
  "query": {
    "filtered": {
      "query": {
        "query_string": {
         # "analyze_wildcard": true,
          "query": query
        }
      },
      "filter": {
        "bool": {
          "must": [
            {
              "range": {
                "@timestamp": {
                  "gte": startTime,
                  "lte": endTime
                }
              }
            }
          ],
          "must_not": []
        }
      }
    }
  },
  "size": 1000000,
#  "sort": [
#    {
#      "@timestamp": {
#        "order": "desc",
#        "unmapped_type": "boolean"
#      }
#    }
#  ],
#  "aggs": {
#    "2": {
#      "date_histogram": {
#        "field": "@timestamp",
#        "interval": "30s",
#        "pre_zone": "-07:00",
#  "aggs": {
#    "2": {
#      "date_histogram": {
#        "field": "@timestamp",
#        "interval": "30s",
#        "pre_zone": "-07:00",
       # "pre_zone_adjust_large_interval": true,
#        "min_doc_count": 0,
#        "extended_bounds": {
#          "min": startTime,
#          "max": endTime
#       }
#      }
#    }
#  },
  "fields": [
    "*",
    "_source"
  ],
  "script_fields": {},
  "fielddata_fields": [
    "@timestamp"
  ]
}
)

#send email
def sendMail():
	with open(fileName,'r') as content_file:
		message = content_file.read()
	#print message
	#Send the mail
	server.sendmail(fromAddr, toAddr, message)


# This method adds or modifies the dictionary supplied
def modify(data,name):
	if isinstance(name, dict):
		if not data in name:
			name[data] = {'value':1}
		else:
			name[data]['value'] +=1

def createErrorDict(name,value):
	test[name] = value
	errorDict.update(test)

#def to_markdown(self):
#	table = []
	# first row is heading
#	table.append(self._to_row(self.data[0]))
        # separator line...
#        table.append(self._to_row(["-"]*len(self.data[-1])))
#        for row in self.data[1:]:
#            table.append(self._to_row(row))
#        return "\n".join(table)

#

#print json.dumps(res)
for hit in res['hits']['hits']:
	if hit['_source']['ar_tag'] in changeSeverity:
		severity[changeSeverity[hit['_source']['ar_tag']]] += 1
	else:
		severity[hit['_source']['ar_severity']] += 1
	modify(hit['_source']['host'],hosts)
	for i in  errorStrings:
		if i in hit['_source']['ar_tag']:
			tmp = hit['_source']['host']
			modify(i,hosts[tmp])


# Create Log report file
f = open(fileName,'w+')
f.write("""From: %s
To: %s
MIME-Version: 1.0
Content-type:
Subject: %s


====TACBOT REPORT====

"""%(fromAddr, toAddr,emailSubject))
f.write("Sev 0 to 6 SYSLOG:\n")

#print "Got %d Sylogs grom %d unique devices" %(res['hits']['total'], len(hosts))
f.write("Got %d Sylogs from %d unique devices\n" %(res['hits']['total'], len(hosts)))

# Print the Number of syslogs for each severity level per day
#print "\nSeverity:\n"
f.write("\nSeverity:\n")
for i in range(0,7):
	#print "severity %d cases = %d" %(i,severity[i])
	f.write("severity %d cases = %d\n" %(i,severity[i]))

# Print all the errors in the following format:
# Error Name:
# Host Name	Total Errors on that host per day 	Total errors of that kind per day
for error in errorStrings:
	#print "\n%s errors:\n" %(error)
	#f.write("\n%s errors:\n" %(error))
	flag = 0
	errorDict={}
	#sorted_list = {}
	#sorted_list = OrderedDict(sorted(hosts.iteritems(),key=lambda x: x[2][error]['value'], reverse=True))
	for k,v in hosts.iteritems():
		if error in v:
			#print "%s:\tTotal Errors:%d\tTotal %s Errors:%d" %(k,v['value'],error,v[error]['value'])
			#f.write("%s:\t%d\n" %(k,v[error]['value']))
			createErrorDict(k.lower(),v[error]['value'])
			flag=1
	if flag:
		f.write("\n%s Errors:\n" %(error))
		sorted_list = {}
		sorted_list = OrderedDict(sorted(errorDict.iteritems(),key=lambda x: x[1], reverse=True))
		i=0
		for k1,v1 in sorted_list.iteritems():
			f.write("%s:\t%d\n" %(k1,v1))
			i +=1
			if i==10:
				break
# Print the Host with the highest number of syslogs per day
# print "\nTop 10 Hosts:\n"
f.write("\nTop 10 Hosts:\n")

sorted_list = {}
sorted_list = OrderedDict(sorted(hosts.iteritems(),key=lambda x: x[1]['value'], reverse=True))
i = 0
for key,value in sorted_list.iteritems():
	#print "%s:%d"%(key,value['value'])
	f.write("%s:%d\n"%(key.lower(),value['value']))
	if i==9:
		break
	else:
		i +=1
f.close()
#print json.dumps(sorted_list)
sendMail()
