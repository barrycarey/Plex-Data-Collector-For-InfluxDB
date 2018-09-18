import configparser
import os
import sys

import requests


class ConfigManager:

    def __init__(self, config):

        print('Loading config: ' + config)

        config_file = os.path.join(os.getcwd(), config)
        if os.path.isfile(config_file):
            self.config = configparser.ConfigParser()
            self.config.read(config_file)
        else:
            print('ERROR: Unable To Load Config File: {}'.format(config_file))
            sys.exit(1)

        self._load_config_values()
        self._validate_plex_servers()
        print('Configuration Successfully Loaded')

    def _load_config_values(self):

        # General
        self.delay = self.config['GENERAL'].getint('Delay', fallback=2)
        self.report_combined = self.config['GENERAL'].get('ReportCombined', fallback=True)

        # InfluxDB
        self.influx_address = self.config['INFLUXDB']['Address']
        self.influx_port = self.config['INFLUXDB'].getint('Port', fallback=8086)
        self.influx_database = self.config['INFLUXDB'].get('Database', fallback='plex_data')
        self.influx_ssl = self.config['INFLUXDB'].getboolean('SSL', fallback=False)
        self.influx_verify_ssl = self.config['INFLUXDB'].getboolean('Verify_SSL', fallback=True)
        self.influx_user = self.config['INFLUXDB'].get('Username', fallback='')
        self.influx_password = self.config['INFLUXDB'].get('Password', fallback='', raw=True)

        # Plex
        self.plex_user = self.config['PLEX']['Username']
        self.plex_password = self.config['PLEX'].get('Password', raw=True)
        plex_https = self.config['PLEX'].getboolean('HTTPS', fallback=False)
        self.conn_security = 'https' if plex_https else 'http'
        self.plex_verify_ssl = self.config['PLEX'].getboolean('Verify_SSL', fallback=False)
        servers = len(self.config['PLEX']['Servers'])

        #Logging
        self.logging_level = self.config['LOGGING']['Level'].upper()

        if servers:
            self.plex_server_addresses = self.config['PLEX']['Servers'].replace(' ', '').split(',')
        else:
            print('ERROR: No Plex Servers Provided.  Aborting')
            sys.exit(1)

    def _validate_plex_servers(self):
        """
        Make sure the servers provided in the config can be resolved.  Abort if they can't
        :return:
        """
        failed_servers = []
        for server in self.plex_server_addresses:
            server_url = '{}://{}:32400'.format(self.conn_security, server)
            try:
                r = requests.get(server_url, verify=self.plex_verify_ssl)
                if r.status_code == 401:
                    continue
                print('Unexpected status code {} from Plex server'.format(str(r.status_code)))
            except ConnectionError as e:
                print('Failed to connect to Plex server ' + server)
                failed_servers.append(server)

        # Do we have any valid servers left?
        # TODO This check is failing even with no bad servers
        if len(self.plex_server_addresses) > len(failed_servers):
            print('INFO: Found {} Bad Server(s).  Removing Them From List'.format(str(len(failed_servers))))
            for server in failed_servers:
                self.plex_server_addresses.remove(server)
        else:
            print('ERROR: No Valid Servers Provided.  Check Server Addresses And Try Again')
            sys.exit(1)
