#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# WPSeku - Wordpress Security Scanner
# by Momo Outaadi (m4ll0k)

from lib.printer import *
from modules.discovery.generic.wpconfig import *
from modules.discovery.generic.wpfile import *
from modules.discovery.generic.wpfpd import *
from modules.discovery.generic.wplisting import *
from modules.discovery.generic.wplogin import *
from modules.discovery.generic.wprobots import *
from modules.discovery.generic.wpversion import *

def generic(url,data,kwargs):
	wpfpd(url,data,kwargs).run()
	wpconfig(url,data,kwargs).run()
	wpfile(url,data,kwargs).run()
	wplisting(url,data,kwargs).run()
	wplogin(url,data,kwargs).run()
	wprobots(url,data,kwargs).run()
	wpversion(url,data,kwargs).run()
	normal('')