# Copyright (c) 2016, The MITRE Corporation
# All rights reserved.

#This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
#See the file "docs/LICENSE" for copying permission.

import os

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

class MAEC50Report(Report):
	'''Generates MAEC 5.0 report.

	Arguments

	TODO: determine what arguments are needed given MAEC5.0 json schemas

	'''

	def run(self,results):
	'''Writes MAEC5.0 report from Cuckoo results.
	@param results: Cuckoo results dictionary.
