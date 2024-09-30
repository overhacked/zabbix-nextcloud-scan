#!/usr/bin/python3

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
        self.requeueDelta = datetime.timedelta(minutes=requeueMinutes)

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

        # Zeitzone extrahieren und ignorieren, da strptime in Python 3 keine %Z mehr unterstützt
        lastScanTimestamp = datetime.datetime.strptime(
            result['scannedAt']['date'],
            '%Y-%m-%d %H:%M:%S.%f'
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
        result['hardeningsMissing'] = sum(1 for isHardened in result['hardenings'].values() if isHardened is False)
        result['headersMissing'] = sum(1 for headerPresent in result['setup']['headers'].values() if headerPresent is False)

        return json.dumps(result, separators=(',', ':'))

    def getFormattedResultJson(self):
        result = self.doScan()

        result['vulnerabilitiesCount'] = len(result['vulnerabilities'])
        result['hardeningsMissing'] = sum(1 for isHardened in result['hardenings'].values() if isHardened is False)
        result['headersMissing'] = sum(1 for headerPresent in result['setup']['headers'].values() if headerPresent is False)

        # Hier erfolgt die formatierte Ausgabe mit Einrückungen
        return json.dumps(result, indent=4, separators=(',', ':'))

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
    parser.add_argument('-V', '--verbose',
                        required=False,
                        default=False,
                        action='store_true',
                        help='Print formatted, human-readable JSON results'
                        )
    args = parser.parse_args()

    if args.debug:
        import logging
        import http.client as http_client  # Updated for Python 3
        http_client.HTTPConnection.debuglevel = 1

        # Initialize logging
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    scanner = NCScan(args.hostname + args.uri, requeueMinutes=args.minutes)

    try:
        if args.verbose:
            # Formatted, human-readable JSON output
            print(scanner.getFormattedResultJson())
        else:
            # Compact JSON output
            print(scanner.getResultJson())
    except requests.exceptions.RequestException:
        name, value, traceback = sys.exc_info()
        print(f"Error: {name} ({value})")
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
