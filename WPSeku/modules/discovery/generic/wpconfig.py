#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# WPSeku - Wordpress Security Scanner
# by Momo Outaadi (m4ll0k)

from lib.request import * 
from lib.printer import *
from lib.check import *
from lib.readfile import *
from os.path import join,realpath

class wpconfig(Request):
	def __init__(self,url,data,kwargs):
		self.url = url 
		self.data = data
		self.kwargs = kwargs
		Request.__init__(self,kwargs)

	def run(self):
		if self.kwargs['verbose'] is True:
			info('Checking wp-config backup file...')
		url = Path(self.url,'wp-config.php')
		resp = self.send(url=url,method="GET")
		if resp.status_code == 200 and resp.content != ("" or None):
			if resp.url == url:
				plus('wp-config.php available at: %s'%resp.url)
		self.wpconfig_backup()

	def wpconfig_backup(self):
		path  = realpath(__file__).split('modules')[0]
		path += "db/backupfile.wpseku"
		for ext in readfile(path):
			url = Path(self.url,"wp-config.php"+ext.decode('utf-8'))
			resp = self.send(url=url,method="GET")
			if resp.status_code == 200 and resp.content != ("" or None):
				if resp.url == url:
					plus('wp-config.php backup was found at: %s'%(resp.url))