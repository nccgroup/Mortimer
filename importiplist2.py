#!/usr/bin/python

# A collection of scripts for processing network forensics type data and intel, mainly into a postgres database.
#
# Released as open source by NCC Group Plc - http://www.nccgroup.com/
#
# Developed for John Green, cirt at nccgroup dot com
#
# https://github.com/nccgroup/mortimer
#
# Released under AGPL see LICENSE for more information

import urllib
import psycopg2
import psycopg2.extras


#resp=urllib.urlopen("http://rules.emergingthreats.net/blockrules/compromised-ips.txt")
resp=urllib.urlopen("http://www.malwaredomainlist.com/hostslist/ip.txt")

conn=psycopg2.connect("dbname=bro")

cur=conn.cursor()

for ip in resp.readlines():
  ip=ip.decode("utf-8").rstrip()
  cur.execute("INSERT INTO malicious (ip,origin) values (%s,%s)", (ip, 'malwaredomain'))

conn.commit()
cur.close()
conn.close()
