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

class wpplugins(Request):
	def __init__(self,url,data,kwargs):
		self.url = url 
		self.data = data
		self.kwargs = kwargs
		Request.__init__(self,kwargs)

	def changelog(self,plugin):
		if self.kwargs['verbose'] is True:
			info('Checking plugins changelog...')
		files = ['changelog.txt','changelog.md','CHANGELOG.txt','changelog',
		         'CHANGELOG.md','ChangeLog.txt','ChangeLog.md','CHANGELOG']
		for file in files:
			url = Path(self.url,'/wp-content/plugins/%s/%s'%(plugin,file))
			resp = self.send(url=url,method="GET")
			if resp.status_code == 200 and resp.content != ("" or None):
				if resp.url == url: 
					more('Changelog: %s'%(resp.url))
					break
	
	def fpd(self,plugin):
		if self.kwargs['verbose'] is True:
			info('Checking plugins full path disclosure...')
		files = ["404.php","archive.php","author.php","comments.php","footer.php",
		         "functions.php","header.php","image.php","page.php","search.php",
		         "single.php","archive.php"]
		for file in files:
			url = Path(self.url,'/wp-content/plugins/%s/%s'%(plugin,file))
			resp = self.send(url=url,method="GET")
			if resp.status_code == 200 and resp.content != ("" or None):
				if resp.url == url:
					if search(decode('<b>Fatal error</b>:'),resp.content,I):
						path_d = findall(decode('<b>(/\S*)</b>'),resp.content)[0]
						more('FPD (Full Path Disclosure): %s'%(path_d.decode('utf-8')))
						break
	
	def license(self,plugin):
		if self.kwargs['verbose'] is True:
			info('Checking plugins license...')
		files = ['license.txt','license.md','LICENSE.md','LICENSE.txt','LICENSE']
		for file in files:
			url = Path(self.url,'/wp-content/plugins/%s/%s'%(plugin,file))
			resp = self.send(url=url,method="GET")
			if resp.status_code == 200 and resp.content != ("" or None):
				if resp.url == url:
					more('License: %s'%(resp.url))
					break
	
	def listing(self,plugin):
		if self.kwargs['verbose'] is True:
			info('Checking plugins directory listing...')
		dirs = ["js","css","images","inc","admin","src","widgets","lib","assets",
				"includes","logs","vendor","core"]
		for dir_ in dirs:
			url = Path(self.url,'/wp-content/plugins/%s/%s'%(plugin,dir_))
			resp = self.send(url=url,method="GET")
			if resp.status_code == 200 and resp.content != ("" or None):
				if search(decode('<title>Index of'),resp.content,I):
					more('Listing: %s'%(resp.url))
	
	def readme(self,plugin):
		if self.kwargs['verbose'] is True:
			info('Checking plugins readme...')
		files = ['readme.txt','readme.md','README.md','README.txt','README','readme']
		for file in files:
			url = Path(self.url,'/wp-content/plugins/%s/%s'%(plugin,file))
			resp = self.send(url=url,method="GET")
			if resp.status_code == 200 and resp.content != ("" or None):
				if resp.url == url:
					more('Readme: %s'%(resp.url))
					break
	def run(self):
		info('Passive enumeration plugins...')
		plugins = self.s_plugins()
		if plugins != []:
			for plugin in plugins:
				plus('Name: %s'%(plugin.decode('utf-8')))
				self.changelog(plugin)
				self.fpd(plugin)
				self.license(plugin)
				self.readme(plugin)
				self.listing(plugin)
				self.dbwpscan(plugin)
		else: plus('Not found plugins with passive enumeration')

	def s_plugins(self):
		plugin = []
		resp = self.send(url=self.url,method="GET")
		plugins = findall(decode('/wp-content/plugins/(.+?)/'),resp.content)
		for pl in plugins:
			if pl not in plugin:
				plugin.append(pl)
		return plugin

	def dbwpscan(self,plugin):
		if self.kwargs['verbose'] is True:
			info('Checking plugin vulnerabilities...')
		plugin = plugin.decode('utf-8')
		url = "https://www.wpvulndb.com/api/v2/plugins/%s"%(plugin)
		resp = self.send(url=url,method="GET")
		print(resp.content)
		if resp.headers['Content-Type'] == 'application/json':
			json = loads(resp.content)
			if json[plugin]:
				if json[plugin]['vulnerabilities']:
					for x in range(len(json[plugin]['vulnerabilities'])):
						more('Title: \033[1;31m%s'%(json[plugin]['vulnerabilities'][x]['title']))
						if json[plugin]['vulnerabilities'][x]['references'] != {}:
							if json[plugin]['vulnerabilities'][x]['references']['url']:
								for y in range(len(json[plugin]['vulnerabilities'][x]['references']['url'])):
									more('Reference: %s'%(json[plugin]['vulnerabilities'][x]['references']['url'][y]))
						more('Fixed in: %s'%(json[plugin]['vulnerabilities'][x]['fixed_in']))
				else: more('Not found vulnerabilities')
			else: more('Not found vulnerabilities')
		else: more('Not found vulnerabilities')
		normal('')