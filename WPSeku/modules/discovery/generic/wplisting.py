#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# WPSeku - Wordpress Security Scanner
# by Momo Outaadi (m4ll0k)

from re import search,findall,I
from os.path import join,realpath
from lib.request import * 
from lib.printer import *
from lib.check import *
from lib.readfile import *

class wplisting(Request):
	def __init__(self,url,data,kwargs):
		self.url = url 
		self.data = data
		self.kwargs = kwargs
		Request.__init__(self,kwargs)

	def run(self):
		if self.kwargs['verbose'] is True:
			info('Checking directory listing...')
		path  = realpath(__file__).split('modules')[0]
		path += "db/dirlisting.wpseku"
		for dir_ in readfile(path):
			url = Path(self.url,dir_.decode('utf-8'))
			resp = self.send(url=url,method="GET")
			if search(decode('<title>Index of /'),resp.content,I):
				plus('Dir "%s" listing enable at: %s'%(dir_.decode('utf-8'),resp.url))