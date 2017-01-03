from urllib.request import Request, urlopen
import base64
import json
import os
import sys
import xml.etree.ElementTree as ET
import time
from urllib.error import HTTPError, URLError
import configparser
import logging

from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBClientError, InfluxDBServerError
from requests.exceptions import ConnectionError


class plexInfluxdbCollector():

    def __init__(self):

        self.config = configManager()

        self.servers = self.config.plex_servers
        self.output = self.config.output
        self.token = None
        self.logger = None
        self._report_combined_streams = True # TODO Move to config
        self.delay = self.config.delay
        self.influx_client = InfluxDBClient(
            self.config.influx_address,
            self.config.influx_port,
            database=self.config.influx_database,
            ssl=self.config.influx_ssl,
            verify_ssl=self.config.influx_verify_ssl
        )
        self._set_logging()
        self._get_auth_token(self.config.plex_user, self.config.plex_password)

    def _set_logging(self):
        """
        Create the logger object if enabled in the config
        :return: None
        """

        if self.config.logging:
            print('Logging is enabled.  Log output will be sent to {}'.format(self.config.logging_file))
            self.logger = logging.getLogger(__name__)
            self.logger.setLevel(self.config.logging_level)
            formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
            fhandle = logging.FileHandler(self.config.logging_file)
            fhandle.setFormatter(formatter)
            self.logger.addHandler(fhandle)

    def send_log(self, msg, level):
        """
        Used as a shim to write log messages.  Allows us to sanitize input before logging
        :param msg: Message to log
        :param level: Level to log message at
        :return: None
        """

        if not self.logger:
            return

        # Make sure a good level was given
        if not hasattr(self.logger, level):
            self.logger.error('Invalid log level provided to send_log')
            return

        output = self._sanitize_log_message(msg)

        log_method = getattr(self.logger, level)
        log_method(output)

    def _sanitize_log_message(self, msg):
        """
        Take the incoming log message and clean and sensitive data out
        :param msg: incoming message string
        :return: cleaned message string
        """
        for server in self.servers:
            msg = msg.replace(server, '*******')
        return msg

    def _get_auth_token(self, username, password):
        """
        Make a reqest to plex.tv to get an authentication token for future requests
        :param username: Plex Username
        :param password: Plex Password
        :return:
        """

        print('Getting Auth Token For User {}'.format(username))

        self.send_log('Attempting to get authentication token', 'info')

        auth_string = '{}:{}'.format(username, password)
        base_auth = base64.encodebytes(bytes(auth_string, 'utf-8'))
        req = Request('https://plex.tv/users/sign_in.json')
        req = self._set_default_headers(req)
        req.add_header('Authorization', 'Basic {}'.format(base_auth[:-1].decode('utf-8')))

        try:
            result = urlopen(req, data=b'').read()
        except HTTPError as e:
            print('Failed To Get Authentication Token')
            if e.code == 401:
                print('This is likely due to a bad username or password')
                self.send_log('Failed to get token due to bad username/password', 'error')
            else:
                print('Maybe this will help:')
                print(e)
                self.send_log('Failed to get authentication token.  No idea why', 'error')
            sys.exit(1)

        output = json.loads(result.decode('utf-8'))

        # Make sure we actually got a token back
        if 'authToken' in output['user']:
            self.token = output['user']['authToken']
        else:
            print('Something Broke \n We got a valid response but for some reason there\'s no auth token')
            sys.exit(1)

        print('Successfully Retrieved Auth Token Of: {}'.format(self.token))
        self.send_log('Success.  We got the token', 'info')

    def _set_default_headers(self, req):
        """
        Sets the default headers need for a request
        :param req:
        :return:
        """

        self.send_log('Adding Request Headers', 'info')

        headers = {
            'X-Plex-Client-Identifier': 'Plex InfluxDB Collector',
            'X-Plex-Product': 'Plex InfluxDB Collector',
            'X-Plex-Version': '1',
            'X-Plex-Token': self.token
        }

        for k, v in headers.items():
            if k == 'X-Plex-Token' and not self.token:  # Don't add token if we don't have it yet
                continue

            req.add_header(k, v)

        return req

    def get_active_streams(self):
        """
        Processes the Plex session list
        :return:
        """
        self.send_log('Getting active streams', 'info')
        active_streams = {}

        for server in self.servers:
            req_uri = 'http://{}:32400/status/sessions'.format(server)

            self.send_log('Attempting to get all libraries with URL: {}'.format(req_uri), 'info')

            req = Request(req_uri)
            self._set_default_headers(req)

            # TODO figured out which exceptions to catch here
            result = urlopen(req).read().decode('utf-8')

            streams = ET.fromstring(result)

            active_streams[server] = streams

        self._process_active_streams(active_streams)

    def _get_session_id(self, stream):
        """
        Find a unique key to identify the stream.  In most cases it will be the sessionKey.  If this does not exist,
        fall back to the TranscodeSession key.
        :param stream: XML object of the stream
        :return:
        """
        session = stream.find('Session')

        if 'sessionKey' in stream.attrib:
            return stream.attrib['sessionKey']

        if session:
            return session.attrib['id']

        transcodeSession = stream.find('TranscodeSession')

        if transcodeSession:
            return transcodeSession.attrib['id']

        return 'N/A'

    def _process_active_streams(self, stream_data):
        """
        Take an object of stream data and create Influx JSON data
        :param stream_data:
        :return:
        """

        self.send_log('Processing Active Streams', 'info')

        combined_streams = 0

        for host, streams in stream_data.items():

            combined_streams += len(streams)

            # Record total streams
            total_stream_points = [
                {
                    'measurement': 'active_streams',
                    'fields': {
                        'active_streams': len(streams)
                    },
                    'tags': {
                        'host': host
                    }
                }
            ]

            self.write_influx_data(total_stream_points)

            for stream in streams:

                session_id = self._get_session_id(stream)

                if stream.attrib['type'] == 'movie':
                    media_type = 'Movie'
                elif stream.attrib['type'] == 'episode':
                    media_type = 'TV Show'
                elif stream.attrib['type'] == 'track':
                    media_type = 'Music'
                else:
                    media_type = 'Unknown'

                # Build the title. TV and Music Have a root title plus episode/track name.  Movies don't
                if 'grandparentTitle' in stream.attrib:
                    full_title = stream.attrib['grandparentTitle'] + ' - ' + stream.attrib['title']
                else:
                    full_title = stream.attrib['title']

                if media_type != 'Music':
                    resolution = stream.find('Media').attrib['videoResolution'] + 'p'
                else:
                    resolution = stream.find('Media').attrib['bitrate'] + 'Kbps'

                self.send_log('Title: {}'.format(full_title), 'debug')
                self.send_log('Media Type: {}'.format(media_type), 'debug')
                self.send_log('Session ID: {}'.format(session_id), 'debug')
                self.send_log('Title: {}'.format(resolution), 'debug')

                """
                playing_points = [
                    {
                        'measurement': 'now_playing',
                        'fields': {
                            'session_id': session_id
                         },
                        'tags': {
                            'host': host,
                            'player_address': stream.find('Player').attrib['address'],

                            'media_type': media_type,
                            'resolution': resolution,
                            'user': stream.find('User').attrib['title'],
                            'stream_title': full_title,
                            'player': stream.find('Player').attrib['title'],
                        }
                    }
                ]

                # Working Layout
                """
                playing_points = [
                    {
                        'measurement': 'now_playing',
                        'fields': {
                            'stream_title': full_title,
                            'player': stream.find('Player').attrib['title'],
                            'user': stream.find('User').attrib['title'],
                            'resolution': resolution,
                            'media_type': media_type,
                        },
                        'tags': {
                            'host': host,
                            'player_address': stream.find('Player').attrib['address'],
                            'session_id': session_id
                        }
                    }
                ]

                self.write_influx_data(playing_points)

        if self._report_combined_streams:
            combined_stream_points = [
                {
                    'measurement': 'active_streams',
                    'fields': {
                        'active_streams': combined_streams
                    },
                    'tags': {
                        'host': 'All'
                    }
                }
            ]

            self.write_influx_data(combined_stream_points)

    def get_library_data(self):
        """
        Get all library data for each provided server.
        """
        # TODO This might take ages in large libraries.  Add a seperate delay for this check
        lib_data = {}

        for server in self.servers:
            req_uri = 'http://{}:32400/library/sections'.format(server)
            self.send_log('Attempting to get all libraries with URL: {}'.format(req_uri), 'info')
            req = Request(req_uri)
            req = self._set_default_headers(req)

            try:
                result = urlopen(req).read().decode('utf-8')
            except URLError as e:
                msg = 'ERROR: Failed To Get Library Data From {}'.format(req_uri)
                print(msg)
                print(e)

                self.send_log(msg, 'error')

                return

            libs = ET.fromstring(result)

            self.send_log('We found {} libraries'.format(str(len(libs))), 'info')

            host_libs = []
            if len(libs) > 0:
                for i in range(1, len(libs) + 1):
                    req_uri = 'http://{}:32400/library/sections/{}/all'.format(server, i)
                    self.send_log('Attempting to get library {} with URL: {}'.format(i, req_uri), 'info')
                    req = Request(req_uri)
                    req = self._set_default_headers(req)

                    try:
                        result = urlopen(req).read().decode('utf-8')
                    except URLError as e:
                        self.send_log('Failed to get library {}.  {}'.format(i, e), 'error')
                        continue

                    lib_root = ET.fromstring(result)
                    host_libs.append({
                        'name': lib_root.attrib['librarySectionTitle'],
                        'items': len(lib_root)
                    })
                lib_data[server] = host_libs

        self._process_library_data(lib_data)

    def _process_library_data(self, lib_data):
        """
        Breakdown the provided library data and format for InfluxDB
        """

        self.send_log('Processing Library Data', 'info')

        for host, data in lib_data.items():
            for lib in data:
                lib_points = [
                    {
                        'measurement': 'libraries',
                        'fields': {
                            'items': lib['items']
                        },
                        'tags': {
                            'lib_name': lib['name'],
                            'host': host
                        }
                    }
                ]
                self.write_influx_data(lib_points)

    def write_influx_data(self, json_data):
        """
        Writes the provided JSON to the database
        :param json_data:
        :return:
        """
        if self.output:
            print(json_data)

        self.send_log('Writing Data To InfluxDB ', 'info')

        try:
            self.influx_client.write_points(json_data)
        except (InfluxDBClientError, ConnectionError, InfluxDBServerError) as e:
            if hasattr(e, 'code') and e.code == 404:
                print('Database {} Does Not Exist.  Attempting To Create')

                self.send_log('Database {} Does Not Exist.  Attempting To Create', 'error')

                # TODO Grab exception here
                self.influx_client.create_database(self.config.influx_database)
                self.influx_client.write_points(json_data)

                return

            self.send_log('Failed to write data to InfluxDB', 'error')

            print('ERROR: Failed To Write To InfluxDB')
            print(e)

    def run(self):

        print('Starting Monitoring Loop \n ')
        self.send_log('Starting Monitoring Loop', 'info')

        if not self.output:
            print('There will be no further output unless something explodes')

        while True:
            self.get_library_data()
            self.get_active_streams()
            time.sleep(self.delay)


class configManager():

    def __init__(self):
        print('Loading Configuration File')
        config_file = os.path.join(os.getcwd(), 'config.ini')
        if os.path.isfile(config_file):
            self.config = configparser.ConfigParser()
            self.config.read(config_file)
        else:
            print('ERROR: Unable To Load Config File')
            sys.exit(1)

        self._load_config_values()
        self._validate_plex_servers()
        self._validate_logging_level()
        print('Configuration Successfully Loaded')

    def _load_config_values(self):

        # General
        self.delay = self.config['GENERAL'].getint('Delay', fallback=2)
        self.output = self.config['GENERAL'].getboolean('Output', fallback=True)

        # InfluxDB
        self.influx_address = self.config['INFLUXDB']['Address']
        self.influx_port = self.config['INFLUXDB'].getint('Port', fallback=8086)
        self.influx_database = self.config['INFLUXDB'].get('Database', fallback='plex_data')
        self.influx_ssl = self.config['INFLUXDB'].getboolean('SSL', fallback=False)
        self.influx_verify_ssl = self.config['INFLUXDB'].getboolean('Verify_SSL', fallback=True)

        # Plex
        self.plex_user = self.config['PLEX']['Username']
        self.plex_password = self.config['PLEX']['Password']
        servers = len(self.config['PLEX']['Servers'])

        #Logging
        self.logging = self.config['LOGGING'].getboolean('Enable', fallback=False)
        self.logging_level = self.config['LOGGING']['Level'].lower()
        self.logging_file = self.config['LOGGING']['LogFile']
        self.logging_hide_server = self.config['LOGGING'].getboolean('HideServer', fallback=True)

        if servers:
            self.plex_servers = self.config['PLEX']['Servers'].replace(' ', '').split(',')
        else:
            print('ERROR: No Plex Servers Provided.  Aborting')
            sys.exit(1)

    def _validate_plex_servers(self):
        """
        Make sure the servers provided in the config can be resolved.  Abort if they can't
        :return:
        """
        failed_servers = []
        for server in self.plex_servers:
            server_url = 'http://{}:32400'.format(server)
            try:
                urlopen(server_url)
            except URLError as e:
                # If it's 401 it's a valid server but we're not authorized yet
                if hasattr(e, 'code') and e.code == 401:
                    continue
                print('ERROR: Failed To Connect To Plex Server At: ' + server_url)
                failed_servers.append(server)

        # Do we have any valid servers left?
        if len(self.plex_servers) != len(failed_servers):
            print('INFO: Found {} Bad Server(s).  Removing Them From List'.format(str(len(failed_servers))))
            for server in failed_servers:
                self.plex_servers.remove(server)
        else:
            print('ERROR: No Valid Servers Provided.  Check Server Addresses And Try Again')

    def _validate_logging_level(self):
        """
        Make sure we get a valid logging level
        :return:
        """

        valid_levels = ['critical', 'error', 'warning', 'info', 'debug']
        if self.logging_level in valid_levels:
            self.logging_level = self.logging_level.upper()
            return
        else:
            print('Invalid logging level provided. {}'.format(self.logging_level))
            print('Logging will be disabled')
            print('Valid options are: {}'.format(', '.join(valid_levels)))
            self.logging = None


def main():

    collector = plexInfluxdbCollector()
    collector.run()


if __name__ == '__main__':
    main()
