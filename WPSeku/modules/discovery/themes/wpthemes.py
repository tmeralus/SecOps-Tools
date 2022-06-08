#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# WPSeku - Wordpress Security Scanner
# by Momo Outaadi (m4ll0k)

from lib.request import * 
from lib.printer import *
from lib.check import *
from json import loads
from re import search,findall,I

class wpthemes(Request):
	def __init__(self,url,data,kwargs):
		self.url = url 
		self.data = data
		self.kwargs = kwargs
		Request.__init__(self,kwargs)

	def changelog(self,theme):
		if self.kwargs['verbose'] is True:
			info('Checking themes changelog...')
		files = ['changelog.txt','changelog.md','CHANGELOG.txt','changelog',
		         'CHANGELOG.md','ChangeLog.txt','ChangeLog.md','CHANGELOG']
		for file in files:
			url = Path(self.url,'/wp-content/themes/%s/%s'%(theme,file))
			resp = self.send(url=url,method="GET")
			if resp.status_code == 200 and resp.content != ("" or None):
				if resp.url == url: 
					more('Changelog: %s'%(resp.url))
					break
	
	def fpd(self,theme):
		if self.kwargs['verbose'] is True:
			info('Checking themes full path disclosure...')
		files = ["404.php","archive.php","author.php","comments.php","footer.php",
		         "functions.php","header.php","image.php","page.php","search.php",
		         "single.php","archive.php"]
		for file in files:
			url = Path(self.url,'/wp-content/themes/%s/%s'%(theme,file))
			resp = self.send(url=url,method="GET")
			if resp.status_code == 200 and resp.content != ("" or None):
				if resp.url == url:
					if search(decode('<b>Fatal error</b>:'),resp.content,I):
						path_d = findall(decode('<b>(/\S*)</b>'),resp.content)[0]
						more('FPD (Full Path Disclosure): %s'%(path_d.decode('utf-8')))
						break
	
	def license(self,theme):
		if self.kwargs['verbose'] is True:
			info('Checking themes license...')
		files = ['license.txt','license.md','LICENSE.md','LICENSE.txt','LICENSE']
		for file in files:
			url = Path(self.url,'/wp-content/themes/%s/%s'%(theme,file))
			resp = self.send(url=url,method="GET")
			if resp.status_code == 200 and resp.content != ("" or None):
				if resp.url == url:
					more('License: %s'%(resp.url))
					break
	
	def listing(self,theme):
		if self.kwargs['verbose'] is True:
			info('Checking themes directory listing...')
		dirs = ["js","css","images","inc","admin","src","widgets","lib","assets",
				"includes","logs","vendor","core"]
		for dir_ in dirs:
			url = Path(self.url,'/wp-content/themes/%s/%s'%(theme,dir_))
			resp = self.send(url=url,method="GET")
			if resp.status_code == 200 and resp.content != ("" or None):
				if search(decode('<title>Index of'),resp.content,I):
					more('Listing: %s'%(resp.url))
	
	def readme(self,theme):
		if self.kwargs['verbose'] is True:
			info('Checking themes readme...')
		files = ['readme.txt','readme.md','README.md','README.txt','README','readme']
		for file in files:
			url = Path(self.url,'/wp-content/themes/%s/%s'%(theme,file))
			resp = self.send(url=url,method="GET")
			if resp.status_code == 200 and resp.content != ("" or None):
				if resp.url == url:
					more('Readme: %s'%(resp.url))
					break
	def run(self):
		info('Passive enumeration themes...')
		themes = self.s_themes()
		if themes != []:
			for theme in themes:
				plus('Name: %s'%(theme.decode('utf-8')))
				self.changelog(theme)
				self.fpd(theme)
				self.license(theme)
				self.readme(theme)
				self.listing(theme)
				self.dbwpscan(theme)
		else: plus('Not found themes with passive enumeration')

	def s_themes(self):
		theme = []
		resp = self.send(url=self.url,method="GET")
		themes = findall(decode('/wp-content/themes/(.+?)/'),resp.content)
		for pl in themes:
			if pl not in theme:
				theme.append(pl)
		return theme

	def dbwpscan(self,theme):
		if self.kwargs['verbose'] is True:
			info('Checking theme vulnerabilities...')
		theme = theme.decode('utf-8')
		url = "https://www.wpvulndb.com/api/v2/themes/%s"%(theme)
		resp = self.send(url=url,method="GET")
		if resp.headers['Content-Type'] == 'application/json':
			json = loads(resp.content)
			if json[theme]:
				if json[theme]['vulnerabilities']:
					for x in range(len(json[theme]['vulnerabilities'])):
						more('Title: \033[1;31m%s'%(json[theme]['vulnerabilities'][x]['title']))
						if json[theme]['vulnerabilities'][x]['references'] != {}:
							if json[theme]['vulnerabilities'][x]['references']['url']:
								for y in range(len(json[theme]['vulnerabilities'][x]['references']['url'])):
									more('Reference: %s'%(json[theme]['vulnerabilities'][x]['references']['url'][y]))
						more('Fixed in: %s'%(json[theme]['vulnerabilities'][x]['fixed_in']))
				else: more('Not found vulnerabilities')
			else: more('Not found vulnerabilities')
		else: more('Not found vulnerabilities')
		normal('')