#!/usr/bin/python

import argparse
import requests
import json
import datetime
import sys

class NCScan:
    
    API_BASE_URI = 'https://scan.nextcloud.com/api'

    def __init__(self, uri, requeueMinutes=1440):
        self.uri = uri
        self.uuid = None
        self.requeueDelta=datetime.timedelta(minutes=requeueMinutes)

    def _post(self, endpoint, **kwargs):
        headers = {'X-CSRF': 'true'}
        r = requests.post(self.API_BASE_URI + '/' + endpoint, data=kwargs, headers=headers)
        r.raise_for_status()
        return r

    def _get(self, endpoint, **kwargs):
        r = requests.get(self.API_BASE_URI + '/' + endpoint, params=kwargs)
        r.raise_for_status()
        return r
        
    def requestUUID(self):
        response = self._post('queue', url=self.uri)
        self.uuid = response.json()['uuid']
        return self.uuid

    def getUUID(self):
        if self.uuid is None:
            self.requestUUID()

        return self.uuid

    def requestRequeue(self):
        response = self._post('requeue', url=self.uri)
        return response

    def requestResult(self):
        response = self._get('result/' + self.getUUID())
        responseJson = response.json()
        return responseJson

    def doScan(self):
        result = self.requestResult()
        lastScanTimestamp = datetime.datetime.strptime(
            result['scannedAt']['date']
                + ' '
                + result['scannedAt']['timezone'],
            '%Y-%m-%d %H:%M:%S.%f %Z'
        )
        scanDelta = datetime.datetime.utcnow() - lastScanTimestamp
        result['secondsSinceScan'] = int(scanDelta.total_seconds())
        if scanDelta >= self.requeueDelta:
            self.requestRequeue()
            result['requeueRequested'] = True

        return result

    def getResultJson(self):
        result = self.doScan()

        result['vulnerabilitiesCount'] = len(result['vulnerabilities'])
        result['hardeningsMissing'] = sum( 1 for isHardened in result['hardenings'].values() if isHardened == False )
        result['headersMissing'] = sum( 1 for headerPresent in result['setup']['headers'].values() if headerPresent == False )

        return json.dumps(result, separators=(',',':'))

def main():
    parser = argparse.ArgumentParser(
                                    description='Run a Nextcloud security scan at scan.nextcloud.org',
                                    )
    parser.add_argument('hostname',
                        help='Publicly-available hostname of the Nextcloud instance to scan'
                       )
    parser.add_argument('-u', '--uri',
                        required=False,
                        default='/',
                        help='Base URI of the Nextcloud instance (default: "%(default)s")'
                       )
    parser.add_argument('-m', '--minutes',
                        required=False,
                        default=1440,
                        type=int,
                        help='Number of minutes after which to initiate a re-scan (default: %(default)s)'
                       )
    parser.add_argument('-D', '--debug',
                        required=False,
                        default=False,
                        action='store_true'
                       )
    args = parser.parse_args()

    if args.debug:
        import logging
        import httplib as http_client
        http_client.HTTPConnection.debuglevel = 1

        # You must initialize logging, otherwise you'll not see debug output.
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    scanner = NCScan(args.hostname + args.uri, requeueMinutes=args.minutes)

    try:
        print(scanner.getResultJson()) 
    except requests.exceptions.RequestException:
        (name, value, traceback) = sys.exc_info()
        print("Error: ", name, " (", value, ")")
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
