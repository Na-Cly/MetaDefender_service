import requests
import json
import time
import xml.parsers.expat
import hashlib
from datetime import datetime

from django.conf import settings
from django.template.loader import render_to_string

from crits.core.data_tools import create_zip
from crits.services.core import Service, ServiceConfigError

from . import forms
class MetaDefenderService(Service):
    """
    Pushes a sample to your a MetaDefender instance and scans the sample with different AV engines.
    Must Speicify api_key and url in the service settings.
    """

    name = "MetaDefender"
    version = "1.0.0"
    supported_types = ['Sample']
    description = "Send a sample to a MetaDefender instance."

    @staticmethod
    def get_config(existing_config):
        config = {}
        fields = forms.MetaDefenderConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.MetaDefenderConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]

        return display_config

    @staticmethod
    def parse_config(config):
        if not config['url']:
            raise ServiceConfigError("URL required.")
        if not config['api_key']:
            raise ServiceConfigError("api_key required.")


    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.MetaDefenderConfigForm(initial=config),
                                 'config_error': None})
        form = forms.MetaDefenderConfigForm
        return form, html

    @staticmethod
    def valid_for(obj):
        if obj.filedata.grid_id == None:
            raise ServiceConfigError("Missing filedata.")

     # Fetch Scan Result by File Hash via MetaDefender Core
    def hashScanResult(self, file_hash, url, headers):
        api_url = url + "/metascan_rest/hash/" + file_hash
        response = requests.get(api_url, headers=headers)
        data = response.json()
        report = [False, data]
        if file_hash not in data.keys():
            report[0] = True
        return report

    # Scan a File via MetaDefender Core
    def uploadFile(self, file_name, url, headers):
        api_url = url + "/metascan_rest/file"
        files = file_name
        response = requests.post(api_url, data=files, headers=headers)
       
        data = response.json()
        return data["data_id"]

    # Fetch Scan Result (by Data ID) via MetaDefender Core
    def retrieveScanResult(self, file_data_id, url, headers):
        api_url = url + "/metascan_rest/file/" + file_data_id
        response = requests.get(api_url, headers=headers)
        data = response.json()
        # Ensure that we have the full scan report, especially useful for scanning large files
        while data['scan_results']['progress_percentage'] < 100:
            response = requests.get(api_url, headers=headers)
            data = json.loads(response.text)
            time.sleep(1)
        return data

    def run(self, obj, config): 
        api = API(config['api_key'])
        url = config['url']
        headers = {"apikey" : api_key}

        data = obj.filedata.read()
        zipdata = create_zip([("samples", data)])
        
        # SHA1 hash of the given file
        file_hash = obj.sha1

        if config.get('use_proxy'):
            self._debug("MetaDefender: proxy handler set to: %s" % settings.HTTP_PROXY)
            #updated for requests
            proxy_handler = {'http': settings.HTTP_PROXY, 'https' : settings.HTTP_PROXY}
        else:
            self._debug("MetaDefender: proxy handler unset")


        # was this file scanned/uploaded already?
        hash_found = api.hashScanResult(file_hash, url, headers)[0]

        # if so we can obtain the scan result via the file's hash
        file_scan_result = api.hashScanResult(file_hash, url, headers)[1]

        if not hash_found:

            # scan/upload the file if we din't obtain a scan result via the file's hash; save the files data_id
            file_data_id = api.uploadFile(data, url)

            # obtain the scan results via the file's data_id
            file_scan_result = api.retrieveScanResult(file_data_id, url, headers)

        
        for engine in file_scan_result["scan_results"]["scan_details"]:
            
            #stores the threat intel restults. More data could be pulled from the results json, but this was sufficient for my purpose.
            r = str(file_scan_result["scan_results"]["scan_details"][engine]['threat_found'])
            if r == '':
                r = 'No Threat Detected'
            
            #add result to the table.
            self._add_result('av_result', str(r), {"engine":str(engine), "date":datetime.now().isoformat()})

