Mortimer
======================
A collection of scripts for processing network forensics type data and intel, mainly into a postgres database.

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed for John Green, cirt at nccgroup dot com

https://github.com/nccgroup/mortimer

Released under AGPL see LICENSE for more information

* broimport.py: Imports bro logs into postgres database.  Parses bro header to create table and maps bro data types to postgres

* extract-all.bro: Bro script to extract files from http/smtp etc

* importdomain2ip.py: Some demo scripts to import IP intelligence from various locations. YMMV

* load_geoip.py: Script I found on the interwebs to import geoip csv files into postgres.

* importgoogle.py: Imports google safe browsing database (see wiki).  Required APIKEY

* checkfull.py: Given partial match from GSB database request full SHA hash from Google

* importdomainlist_malicious.py

* importiplist_malicious.py

* importiplist2.py






