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
import sys

url=sys.argv[1]
name=sys.argv[2]


resp=urllib.urlopen(url)

conn=psycopg2.connect("dbname=bgp")

cur=conn.cursor()

for ip in resp.readlines():
  ip=ip.decode("utf-8").rstrip()
  cur.execute("INSERT INTO malicious (netblock,origin) values (%s,%s)", (ip, name))

conn.commit()
cur.close()
conn.close()
