# zabbix-nextcloud-scan
Nextcloud Security Scan monitoring for Zabbix 3.4+

## Requirements

* Zabbix 3.4+
* Python 2 installed on your Zabbix server

## Installation

1. Copy `nextcloud_scan.py` to your Zabbix installation's `ExternalScripts` folder (default: `$ZABBIX_DATA_DIR/externalscripts`). Make sure it is `chmod a+x`
1. You may need to change the hashbang (`#!`) line at the top of the script to read `#!/usr/bin/python2` if your installation's default `/usr/bin/python` is Python 3.
1. Import `zbx_template_nextcloud_scan.xml` to your Zabbix Templates
1. Assign the template to a host. It is set to update every 1 day by default, so you could be waiting a while for data. If you want to verify that the script is working, change the update interval for the 'Nextcloud Security Scan JSON Result' item to something less, like 1m.
