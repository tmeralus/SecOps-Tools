#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# WPSeku - Wordpress Security Scanner
# by Momo Outaadi (m4ll0k)

from lib.request import * 
from lib.printer import *
from lib.check import *

class wplogin(Request):
	def __init__(self,url,data,kwargs):
		self.url = url 
		self.data = data
		self.kwargs = kwargs
		Request.__init__(self,kwargs)

	def run(self):
		if self.kwargs['verbose'] is True:
			info('Checking wp-loging protection...')
		url = Path(self.url,'wp-login.php')
		resp = self.send(url=url,method="GET")
		if resp.status_code not in range(200,299):
			plus('WordPress login is protected by WAF')