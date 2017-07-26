# Copyright (c) 2017, The MITRE Corporation
# All rights reserved.

# MAEC 5.0 Cuckoo Report Module
# BETA - 07/14/2017

# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

# NOTE: For use w/ Cuckoo 2.0.x you'll likely need to edit the "configuration"
# dictionary in common/config.py in order for this module to work.
# Specifically, you'll want to add a new entry in the "reporting" subkey:
# "reporting" : { "maecreport" : { "enabled": Boolean(False) } }

# You'll also need to add a new entry into your conf/reporting.conf:
# [maecreport]
# enabled = yes


import json
import os
import re
import uuid

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError


'''
TODO
--Update and further refine mappings
--More testing! Especially around network actions/mappings
--Add Other MAEC features:
  --AV Results
  --Behaviors & Signatures
--Update/add comments
'''

maec50_package = {
    "type": "package",
    "id": None,
    "schema_version" : 5.0,
    "objects": [],
    "observable_objects": {}
}

'''
Map: cuckoo file type -> mime type
    Note: most of the file type strings listed below are not
    the complete label found in cuckoo report but are substrings
    found in those labels. For example, "PNG image data" is a 
    substring found in all type labels for .png files. But each 
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

class MaecReport(Report):
    '''
    Generates MAEC 5.0 report.
    '''

    def run(self,results):
        '''Writes MAEC5.0 report from Cuckoo results.
        @param results: Cuckoo results dictionary.
        '''
        self.primaryInstance = None
        self.currentObjectIndex = 0
        self.pidActionMap = {}
        self.pidObjectMap = {}
        self.objectMap = {}
        self.apiMappings = {}
        self.results = results
        self.setup()
        self.addDroppedFiles()
        self.mapAPICalls()
        self.addProcessTree()
        self.output()

    '''
    Setup core MAEC fields and types
    '''
    def setup(self):
        self.package = maec50_package
        # Package ID
        self.package['id']= "package--" + str(uuid.uuid4())
        # Load the JSON mappings
        mappings_file = os.path.dirname(os.path.realpath(__file__)) + '/maec_api_call_mappings.json'
        with open(mappings_file) as f:
            self.apiMappings = json.load(f)
        # Set up the primary Malware Instance
        self.setupPrimaryMalwareInstance()

    '''
    Create and return a Cyber Observable Object ID
    '''
    def createObjID(self):
        id = str(self.currentObjectIndex)
        self.currentObjectIndex += 1
        return id

    '''
    Create a base Malware Instance
    '''
    def createMalwareInstance(self, file_data):
        malwareInstance = {
            "type": "malware-instance"
        }

        malwareInstance["id"] = "malware-instance--" + str(uuid.uuid4())

        # Create file object for the malware instance object
        file_obj_id, file_obj = self.createFileObj(file_data)

        # Put instance object reference in malware instance
        malwareInstance['instance_object_refs'] = [file_obj_id]

        # Insert actual instance object in package.objects
        self.package['observable_objects'][file_obj_id] = file_obj

        # Add malwareInstance to package
        self.package['objects'].append(malwareInstance)

        # Return the Malware Instance
        return malwareInstance

    '''
    Instantiate the primary (target) Malware Instance
    '''
    def setupPrimaryMalwareInstance(self):
        malwareInstance = {}
        if "target" in self.results and self.results['target']['category'] == 'file':
            malwareInstance = self.createMalwareInstance(self.results['target']['file'])

            # Add dynamic features
            malwareInstance['dynamic_features'] = {}
        
            # Grab static strings
            if "strings" in self.results and self.results['strings']:
                malwareInstance["static_features"] = {
                        "strings" : self.results['strings']
                }
            
            #if target malware has virus total scans, add them to the Malware Instance's corresponding STIX file object
            if 'virustotal' in self.results and self.results['virustotal']:
                self.package['observable_objects'][file_obj_id]['extensions'] = {}
                self.package['observable_objects'][file_obj_id]['extensions']['x-maec-avclass'] = self.createAVClassObjList(self.results['virustotal'])
                
        elif "target" in self.results and self.results['target']['category']=='url':
            malwareInstance = {
                "type": "malware-instance"
            }
            malwareInstance['id']= "malware-instance--" + str(uuid.uuid4())
            malawareInstance['instance_object_refs'] = [{
                "type":"url",
                "value": self.results['target']['url']
            }]
            '''TODO: add AV Virus Total scans - does it do it for URLs?'''
            # Add malwareInstance to package
            self.package['objects'].append(malwareInstance)

        if malwareInstance:
            # Add cuckoo information
            tool_id = self.createObjID()
            self.package['observable_objects'][tool_id]={
                "type": "software",
                "name": "Cuckoo Sandbox",
                "version": self.results['info']['version']
            }
            malwareInstance['analyses'] = [
                {
                    "tool_refs":[tool_id],
                    "summary":"Automated analysis conducted by Cuckoo Sandbox",
                    "is_automated": True
                }
            ]
            self.primaryInstance = malwareInstance

    '''
    Add any dropped files as Malware Instances along with the corresponding relationships
    '''
    def addDroppedFiles(self):
        if 'dropped' not in self.results:
            return

        # Grab list of all dropped files- remember package['objects'] is a dict where the key is object-ID
        for f in self.results['dropped']:

            # Create a new Malware Instance for each dropped file
            malwareInstance = self.createMalwareInstance(f)

            # Add relationship object to connect original malware instance and new malware instance (from dropped file)
            self.package['objects'].append(
                {
                    "type": "relationship",
                    "id": "relationship--" + str(uuid.uuid4()),
                    "source_ref": self.primaryInstance['id'],
                    "target_ref": malwareInstance['id'],
                    "relationship_type": "drops"
                }
            )

    '''
    Takes a Cuckoo file dictionary and returns a STIX file object and its reference id
    '''
    def createFileObj(self, cuckoo_file_dict):
        obj_id = self.createObjID()
        file_obj = {
                "type":"file",
                "hashes":{
                    "MD5": cuckoo_file_dict['md5'],
                    "SHA-1": cuckoo_file_dict['sha1'],
                    "SHA-256": cuckoo_file_dict['sha256'],
                    "SHA-512": cuckoo_file_dict['sha512']
                },
                "size":cuckoo_file_dict['size'],
                "name":cuckoo_file_dict['name']
        }

        if 'ssdeep' in cuckoo_file_dict and cuckoo_file_dict['ssdeep']:
            file_obj['hashes']['ssdeep'] = cuckoo_file_dict['ssdeep']
        if 'type' in cuckoo_file_dict and cuckoo_file_dict['type']:
            file_obj['mime_type'] = self._get_mime_type(cuckoo_file_dict['type'])
        
        # If file path given, have to create another STIX object
        # for a directory, then reference it

        # Dropped files use the "file_path" field for the actual directory of dropped file
        if 'filepath' in cuckoo_file_dict and cuckoo_file_dict['filepath']:
            self.createDirectoryFromFilePath(file_obj, cuckoo_file_dict['path'])

        # Target file uses the "path" field for recording directory
        elif "path" in cuckoo_file_dict and cuckoo_file_dict['path']:
            self.createDirectoryFromFilePath(file_obj, cuckoo_file_dict['path'])

        # If file has virusTotal scans, insert them under extensions property
        if 'virustotal' in cuckoo_file_dict and cuckoo_file_dict['virustotal']:
            file_obj['extensions'] = {}
            file_obj['extensions']['x-maec-avclass'] = self.createAVClassObjList(cuckoo_file_dict['virustotal'])
            
        return (obj_id, file_obj)

    '''
    Create and add a Directory to a File
    '''
    def createDirectoryFromFilePath(self, file_obj, path):
        file_name = re.split(r'\\|/', path)[-1]
        # Make sure we have a file name and not just a directory
        if file_name or ('name' in file_obj and file_obj['name'] != path):
            dir_path = path.rstrip(file_name)
            dir_obj_id, dir_obj = self.createDirectoryObj(dir_path)
            # Add the file name to the File Object if it does not already exist
            if 'name' not in file_obj or file_obj['name'] == 'null' or '\\' in file_obj['name'] or '/' in file_obj['name']:
                file_obj['name'] = file_name
            if dir_obj["path"]:
                dedup_dir_obj_id = self.deduplicateObj(dir_obj, dir_obj_id)
                # Insert parent directory reference in file obj
                file_obj['parent_directory_ref'] = dedup_dir_obj_id
        # We actually have a directory and not a file
        else:
            dir_obj_id, dir_obj = self.createDirectoryObj(path)
            file_obj['type'] = 'directory'
            file_obj['path'] = dir_obj['path']
            file_obj.pop('name', None)

    '''
    Create and return a Directory Object from an input path
    '''
    def createDirectoryObj(self, dir_path):
        dir_obj_id = self.createObjID()
        if "\\" in dir_path:
            dir_path = dir_path.rstrip("\\")
        elif "/" in dir_path:
            dir_path = dir_path.rstrip("/")
        dir_obj = {
            'type':'directory',
            'path': dir_path
        }
        return (dir_obj_id, dir_obj)

    '''
    Create a Process Object from a Cuckoo Process and add it to the Objects dictionary
    '''
    def createProcessObj(self, obj):
        proc_obj = {'type' : 'process'}
        proc_obj_id = self.createObjID()
        proc_mappings = {'pid' : 'pid',
                         'process_name' : 'name',
                         'command_line' : 'command_line'}
        # Do the Cuckoo -> Cyber Observable mapping
        for key, value in proc_mappings.items():
            if key in obj:
                proc_obj[value] = obj[key]
       # Do the timestamp conversion
        if 'first_seen' in obj:
            proc_obj['created'] = obj['first_seen'].isoformat()
        # Add the process to the PID -> Object map
        self.pidObjectMap[str(obj['pid'])] = self.deduplicateObj(proc_obj, proc_obj_id)


    '''
    Add HTTP request data to a Network Traffic Object
    '''
    def addHTTPData(self, obj, http_resource, network_obj):
        http_ext = {"request_method": "GET",
                    "request_value": http_resource,
                    "request_header": {"Host": network_obj['value']}}
        # Add the corresponding protocols entry
        if 'protocols' in obj:
            protocols = obj['protocols']
            if 'http' not in protocols:
                protocols.append('http')
        else:
            obj['protocols'] = ['http']
        # Add the extensions data
        if 'extensions' in obj:
            extensions = obj['extensions']
            extensions['http-request-ext'] = http_ext
        else:
            obj['extensions'] = {'http-request-ext': http_ext}


    '''
    Create an IPv4, IPv6, MAC, or Domain Name object
    '''
    def createNetworkObj(self, value, obj):
        http_resource = None
        network_obj = {'value': value}
        network_obj_id = self.createObjID()
        # Determine if we're dealing with an IPv4, IPv6, MAC address or domain name
        # Assume this is an HTTP URL
        if value.startswith("http://"):
            split_val = val.replace("http://", "").split("/", 1)
            network_obj['type'] = 'domain-name'
            network_obj['value'] = split_val[0]
            http_resource = split_val[1]
        # Assume this is an FTP URL
        elif value.startswith("ftp://"):
            split_val = val.replace("ftp://", "").split("/", 1)
            network_obj['type'] = 'domain-name'
            network_obj['value'] = split_val[0]
        # Assume this is an HTTPS URL
        elif value.startswith("https://"):
            split_val = val.replace("htps://", "").split("/", 1)
            network_obj['type'] = 'domain-name'
            network_obj['value'] = split_val[0]
            http_resource = split_val[1]
        # Test for an IPv6 address
        elif re.match("^([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}$", value):
            network_obj['type'] = 'ipv6-addr'
            obj['protocols'] = ['ipv6', 'tcp']
        # Test for a MAC address
        elif re.match("^([0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F])$", value):
            network_obj['type'] = 'mac-addr'
        # Test for an IPv4 address
        elif re.match("^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})){3}$", value):
            network_obj['type'] = 'ipv4-addr'
            obj['protocols'] = ['ipv4', 'tcp']
        else:
            network_obj['type'] = 'domain-name'
        # Add the corresponding HTTP extension data to the object
        if http_resource:
            self.addHTTPData(obj, http_resource, network_obj)
        network_obj_id = self.deduplicateObj(network_obj, network_obj_id)
        return network_obj_id

    '''
    Deduplicate a Cyber Observable Object by checking to see if it already exists in self.objectMap
    '''
    def deduplicateObj(self, obj, obj_id):
        obj_hash = json.dumps(obj, sort_keys=True)
        if obj_hash not in self.objectMap:
            self.package['observable_objects'][obj_id] = obj
            self.objectMap[obj_hash] = obj_id
            return obj_id
        elif obj_hash in self.objectMap:
            return self.objectMap[obj_hash]

    '''
    Map the properties of a Cuckoo-reported Object to its STIX Cyber Observable Representation
    '''
    def mapObjectProperties(self, obj, mapping_entry, arguments):
        obj_dict = {}
        # Handle object extensions
        if "extension" in mapping_entry:
            if "extensions" not in obj:
                obj["extensions"] = {mapping_entry["extension"] : obj_dict}
            else:
                extensions_dict = obj["extensions"]
                if mapping_entry["extension"] in extensions_dict:
                    obj_dict = extensions_dict[mapping_entry["extension"]]
                else:
                    extensions_dict[mapping_entry["extension"]] = obj_dict
        else:
            obj_dict = obj
        # Handle nested properties
        if "/" not in mapping_entry['object_property']:
            obj_dict[mapping_entry['object_property']] = arguments[mapping_entry['cuckoo_arg']]
        else:
            split_props = mapping_entry['object_property'].split("/")
            if len(split_props) == 2:
                if split_props[0] not in obj_dict:
                    val = {}
                    val[split_props[1]] = arguments[mapping_entry['cuckoo_arg']]
                    obj_dict[split_props[0]] = [val]
                else:
                    prop = obj_dict[split_props[0]][0]
                    prop[split_props[1]] = arguments[mapping_entry['cuckoo_arg']]

    '''
    Perform the mappings for input or output objects in an Action
    '''
    def mapObjects(self, action, objects_class, mapping, arguments):
        # Create the Cyber Observable Object
        obj = {}
        obj_id = self.createObjID()
        obj['type'] = mapping[objects_class][0]['object_type']
        # Populate the properties of the Object
        for entry in mapping[objects_class]:
            if entry['cuckoo_arg'] in arguments and arguments[entry['cuckoo_arg']]:
                self.mapObjectProperties(obj, entry, arguments)
        # Make sure that some properties on the Object have actually been set
        if len(obj.keys()) > 1:
            action[objects_class] = []
            real_obj_id = self.postProcessObject(obj, obj_id, arguments)
            action[objects_class].append(real_obj_id)

    '''
    Perform any necessary post-processing on Cyber Observable Objects
    '''
    def postProcessObject(self, obj, obj_id, arguments):
        protocol_mappings = {"1" : "ftp",
                             "3" : "http"}
        registry_type_mappings = {
            0: "REG_NONE",
            1: "REG_SZ",
            2: "REG_EXPAND_SZ",
            3: "REG_BINARY",
            4: "REG_DWORD",
            5: "REG_DWORD_BIG_ENDIAN",
            6: "REG_LINK",
            7: "REG_MULTI_SZ",
            8: "REG_RESOURCE_LIST",
            9: "REG_FULL_RESOURCE_DESCRIPTION",
            10: "REG_RESOURCE_REQUIREMENTS_LIST",
            11: "REG_QWORD",
        }

        if obj['type'] == 'file':
            self.createDirectoryFromFilePath(obj, obj['name'])
        elif obj['type'] == 'windows-registry-key':
            if 'regkey' in arguments and 'regkey_r' in arguments and 'values' in obj:
                obj['key'] = obj['key'].replace("\\" + arguments['regkey_r'], "").rstrip()
            elif 'regkey' in arguments and 'key_name' in arguments and 'values' in obj:
                obj['key'] = obj['key'].replace("\\" + arguments['key_name'], "").rstrip()
            if 'reg_type' in arguments and 'values' in obj and 'data_type' in obj['values'][0]:
                obj['values'][0]['data_type'] = registry_type_mappings.get(
                    obj['values'][0]['data_type'],
                    'REG_INVALID_TYPE')
        elif obj['type'] == 'process':
            if 'filepath' in arguments:
                file_obj = {"name": arguments['filepath']}
                file_obj_id = self.createObjID()
                self.createDirectoryFromFilePath(file_obj, file_obj['name'])
                obj['binary_ref'] = self.deduplicateObj(file_obj, file_obj_id)
        elif obj['type']  == 'network-traffic':
            if 'dst_ref' in obj:
                obj['dst_ref'] = self.createNetworkObj(obj['dst_ref'], obj)
            if 'src_ref' in obj:
                obj['src_ref'] = self.createNetworkObj(obj['src_ref'], obj)
            if 'protocols' in obj:
                if type(obj['protocols']) is not list:
                    obj['protocols'] = [str(obj['protocols'])]
                obj['protocols'] = [protocol_mappings[x] if x in protocol_mappings else x for x in obj['protocols']]
        # Check to see if we already have this object stored in our map
        # If so, replace it with a reference to the existing object
        return self.deduplicateObj(obj, obj_id)

    '''
    Create a MAEC Action from a Cuckoo API call
    '''
    def mapAPIToAction(self, mapping, call):
        action = {
            "type": "malware-action"
        }
        action['id'] = "action--" + str(uuid.uuid4())
        action['name'] = mapping['action_name']
        action['timestamp'] = call['time'].isoformat()
        # Map any input objects
        if 'input_objects' in mapping:
            self.mapObjects(action, "input_objects", mapping, call['arguments'])
        # Map any output objects
        if 'output_objects' in mapping:
            self.mapObjects(action, "output_objects", mapping, call['arguments'])
        self.package['objects'].append(action)
        return action['id']

    '''
    Map a Cuckoo API calls into their MAEC Action equivalent 
    '''
    def mapAPICalls(self):
        for process in self.results.get("behavior", {}).get("processes", []):
            for call in process["calls"]:
                # Make sure we have a mapping for the call
                if call['api'] in self.apiMappings:
                    mapping = self.apiMappings[call['api']]
                    # Perform the actual mapping and create the MAEC Action
                    action_id = self.mapAPIToAction(mapping, call)
                    # Add the Action to the process/action map
                    if str(process['pid']) not in self.pidActionMap:
                        self.pidActionMap[str(process['pid'])] = [action_id]
                    else:
                        process_actions = self.pidActionMap[str(process['pid'])]
                        process_actions.append(action_id)

    '''
    Takes the virusTotal scan dictionary for a file (from Cuckoo report).
    Returns a list of x-maec-avclass objects - this list is
    meant to be nested in a STIX file object to its "extensions" field
    '''
    def createAVClassObjList(self, cuckoo_virusTotal_dict):
        avClassList = []
        for vendor, scan_obj in cuckoo_virusTotal_dict['scans'].items():
            # Only grabbing scan information if the vendor detected the scan object
            if scan_obj['detected'] == True:
                avClassObj = {}
                avClassObj['scan_date'] = cuckoo_virusTotal_dict['scan_date']
                avClassObj['is_detected'] = scan_obj['detected']
                avClassObj['classification_name'] = scan_obj['result']
                avClassObj['av_name']= vendor
                avClassObj['av_vendor'] = vendor
                avClassObj['av_version'] = scan_obj['version']
                avClassObj['av_definition_version'] = scan_obj['update']
                avClassList.append(avClassObj)
        return avClassList

    '''
    Create and return a ProcessTreeNode
    '''
    def createProcessTreeNode(self, process, process_children, is_root):
        process_obj = self.package['observable_objects'][self.pidObjectMap[str(process['pid'])]]
        # Add the parent reference to the Process
        if not is_root and 'parent_ref' not in process_obj:
            process_obj['parent_ref'] = self.pidObjectMap[str(process['ppid'])]
        # Add any child references to the Process
        if str(process['pid']) in process_children:
            process_obj['child_refs'] = [self.pidObjectMap[x] for x in process_children[str(process['pid'])]]
        # Create the Process Tree Node
        node = {"process_ref": self.pidObjectMap[str(process['pid'])]}
        if str(process['pid']) in self.pidActionMap:
            node["initiated_action_refs"] = self.pidActionMap[str(process['pid'])]
        if is_root:
            node["ordinal_position"] = 0
        return node

    '''
    Build and add the Process Tree to the primary Malware Instance
    '''
    def addProcessTree(self):
        process_tree_nodes = []
        process_children = {}
        processes = self.results.get("behavior", {}).get("processes", [])
        process_pids = [str(process['pid']) for process in processes]
        # Iterate through all of the processes to build up the parent/child relationships
        # Also, create the Cyber Observable Process Object if it doesn't already exist
        for process in processes:
            if 'ppid' in process and str(process['ppid']) in process_pids:
                if str(process['ppid']) not in process_children:
                    process_children[str(process['ppid'])] = [str(process['pid'])]
                else:
                    process_children[str(process['ppid'])].append(str(process['pid']))
            # Add the Process Object if it doesn't exist
            # TODO: verify if this actually happens
            if str(process['pid']) not in self.pidObjectMap:
                self.createProcessObj(process)
        # Create the nodes for each Process in the tree
        for process in processes:
            ppid = process['ppid']
            # This is the "root" process
            if str(ppid) not in process_pids:
                node = self.createProcessTreeNode(process, process_children, True)
                process_tree_nodes.append(node)
            else:
                node = self.createProcessTreeNode(process, process_children, False)
                process_tree_nodes.append(node)
        self.primaryInstance['dynamic_features']['process_tree'] = process_tree_nodes

    '''
    Map cuckoo file types to a mime type - update "mime_map" accordingly to support more mime types
    '''
    def _get_mime_type(self, cuckoo_type_desc):
        for cuckoo_file_type, mime_type in mime_map.items():
            if cuckoo_file_type in cuckoo_type_desc:
                return mime_type

    def output(self):
        '''writes report to file'''
        json.dump(self.package, open(os.path.join(self.reports_path, "report.MAEC-5.0.json"), 'w'), indent=4)

