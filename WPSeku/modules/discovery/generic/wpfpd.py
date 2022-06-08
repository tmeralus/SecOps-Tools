#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# WPSeku - Wordpress Security Scanner
# by Momo Outaadi (m4ll0k)

from lib.request import * 
from lib.printer import *
from lib.check import *
from re import search,findall,I

class wpfpd(Request):
	def __init__(self,url,data,kwargs):
		self.url = url
		self.data = data
		self.kwargs = kwargs
		Request.__init__(self,kwargs)

	def run(self):
		if self.kwargs['verbose'] is True:
			info('Checking Full Path Disclosure...')
		url = Path(self.url,"/wp-includes/rss-functions.php")
		resp = self.send(url=url,method="GET")
		if resp.status_code == 200 and resp.content != ("" or None):
			if search(decode('<b>Fatal error</b>:'),resp.content,I):
				path_d = findall(decode('<b>(/\S*)</b>'),resp.content)[0]
				plus('Full Path Disclosure: \033[1;31m%s\033[0m'%(path_d.decode('utf-8')))