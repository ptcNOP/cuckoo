# Copyright (c) 2016, The MITRE Corporation
# All rights reserved.

#This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
#See the file "docs/LICENSE" for copying permission.

import os

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

import mixbox.idgen


'''TODO

-Add function documentation and comments
-Static analysis/check run through
-not tested yet

'''

maec50_package = {
	"type":"package",
	"id": None,
	"schema_version" : 5.0,
	"malware_instances":[],
	"malware_families": [],
	"objects":[],
	"behaviors":[],
	"actions":[],
	"process_trees":[],
	"collections":[],
	"relationships":[]
}

'''map: cuckoo file type -> mime type
	note: most of the file type strings listed below are not
	the complete label found in cuckoo report but are substrings
	found in those labels. For example, "PNG image data" is a 
	substing found in all type labels for .png files. But each 
	.png file type will also have dynamic size info within the label,
	 thus "PNG image data" serves as a catch-all key.
'''
mime_map = {
	"PE32 executable":"application/vnd.microsoft.portable-executable",
	"PNG image data":"image/png",
	"HTML document":"text/html",
	"ASCII test":"text/vnd.ascii-art",
	"UTF-8":"text/plain"
}




class MAEC50Report(Report):
	'''Generates MAEC 5.0 report.

	Arguments

	TODO: determine what arguments are needed given MAEC5.0 json schemas

	'''

	def run(self,results):
	'''Writes MAEC5.0 report from Cuckoo results.
	@param results: Cuckoo results dictionary.
	'''
	self.setup()
	self.setupMalwareInstance()
	self.addDroppedFiles()



	'''grab core MAEC fields and types'''
	def setup(self):
		self.package = maec50_package
		#package ID
		self.package['id']= mixbox.idgen.create_id(prefix="file-object") 



	def setupMalwareInstance(self):
		malwareInstance = {
			"type":"malware-instance"
		}
		
		if "target" in self.results and self.results['target']['category'] == 'file':
			malwareInstance["id"] = mixbox.idgen.create_id(prefix = self.results['target']['file']['md5'])
			file_obj_id, file_obj = createFileObj(self.results['target']['file'])
			#put instance object reference in malware instance
			malwareInstance['instance_object_refs'] = [file_obj_id]
			#insert actual instance object in package.objects
			self.package['objects'][file_obj_id]= file_obj
			
			malwareInstance["static_features"]:[
				{
					"strings":[x for x in self.results['target']['file']['urls']]
				}
			]
			malwareInstance["analysis_metadata"]:[
				{
					"comments":["Analysis conducted by the Cuckoo Sandbox 2.0-RC2"],
					"tool_refs":["Cuckoo Sandbox" ]
				}
			]
			
			#if target malware has virus total scans, add them to the Malware Instance's corresponding STIX file object
			if self.results['virustotal']:
				self.package['objects'][file_obj_id]['extended_properties']['x-maec-avclass'] = createAVClassObjList(self.results['virustotal'])
				
		elif "target" in self.results and self.results['target']['category']=='url':
			malwareInstance['id']= mixbox.idgen.create_id(prefix = hashlib.md5(self.results['target']['file']).hexdigest())
			malawareInstance['instance_object_refs'] = [{
				"type":"url",
				"value": self.results['target']['url']
			}]
			'''TODO: add AV Virus Total scans - does it do it for URLs?'''
		
		self.package['malware_instances'].append(malwareInstance)


	def addDroppedFiles(self):
		if not self.results['dropped']:
			return

		#grab list of all dropped files- remember package['objects'] is a dict where the key is object-ID
	    for f in self.results['dropped']:
			obj_id, file_obj = self.createFileObj(f)
			self.package['objects'][obj_id] = file_obj

			#add relationship object to connect malware instance and dropped file
			self.package['relationships'].append(
				{
					"type":"relationship",
					"id":mixbox.idgen.create_id(prefix="relationship")
					"source_ref": self.package['malware_instances'][0]['id'],
					"target_ref": self.package['objects'][obj_id],
					"relationship_type": "drops"
				}
			)    


	'''takes a Cuckoo file dictionary and returns a 
	STIX file object and its reference id
	'''
	def createFileObj(self, cuckoo_file_dict):
		obj_id = mixbox.idgen.create_id(prefix = 'file-obj')
		file_obj={
				"type":"file",
				"hashes":{
					"MD5": cuckoo_file_dict['md5'],
					"SHA-1": cuckoo_file_dict['sha1'],
					"SHA-256": cuckoo_file_dict['sha256'],
					"SHA-512": cuckoo_file_dict['sha512'],
					"ssdeep": cuckoo_file_dict['ssdeep'],
				},	
				"size":cuckoo_file_dict['size'],
				"name":cuckoo_file_dict['name'],
				"mime_type": self._get_mime_type(cuckoo_file_dict['type'])
		}
		
		#if file path given, have to create another STIX object
		# object for a directory, then reference it
		if cuckoo_file_dict['filepath']:
			dir_obj_id, dir_obj = self.createDirectoryObj(cuckoo_file_dict['filepath'])
			
			#Add directory object to package.objects		
			self.package['objects'][dir_obj_id]= dir_obj

			#insert parent directory reference in file obj
			file_obj['parent_directory_ref'] = dir_obj_id
 

		#if file has virusTotal scans, insert them as extended property
		if cuckoo_file_dict['virustotal']
			file_obj['extended_properties']['x-maec-avclass'] = createAVClassObjList(cuckoo_file_dict['virustotal'])
			
		return (obj_id, file_obj)



	def createDirectoryObj(self, dir_path):
		dir_obj_id= mixbox.idgen.create_id(prefix="directory-obj")
		dir_obj = {
			"type":'directory',
			"path":dir_path
		}
		return (dir_obj_id, dir_obj) 	



	'''takes the virusTotal scan dictionary for a file (from Cuckoo report) and
		returns a list of x-maec-avclass objects - this list is
		meant to be nested in a STIX file object to its "extended_properties" field
	'''
	def createAVClassObjList(self, cuckoo_virusTotal_dict):
		avClassList = []
		for vendor, scan_obj in cuckoo_virusTotal_dict['scans'].items():
			#only grabing scan information if the vendor detected the scan object
			if scan_obj['detected']:
				avClassObj = {}
				avClassObj['scan_date'] = cuckoo_VirusTotal_dict['scan_date']
				avClassObj['is_detected'] = scan_obj['detected']
				avClassObj['classification_name'] = scan_obj['result']
				avClassObj['av_name']= vendor
				avClassObj['av_vendor'] = vendor
				avClassObj['av_version'] = scan_obj['version']
				avClassobj['av_definition_version'] = scan_obj['update']
				
				avClassList.append(avClassObj)
		return avClassList


	#map cuckoo file types to a mime type - update "mime_map" accordingly to support more mime types		
	def _get_mime_type(cuckoo_type_desc):
		for cuckoo_file_type, mime_type in mime_map.items():
			if cuckoo_file_type in cuckoo_type_desc:
				return mime_type

