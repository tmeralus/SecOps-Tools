#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# WPSeku - Wordpress Security Scanner
# by Momo Outaadi (m4ll0k)

def server(headers):
	for key in headers.keys():
		if key.lower() == 'server':
			return headers[key]
	return 