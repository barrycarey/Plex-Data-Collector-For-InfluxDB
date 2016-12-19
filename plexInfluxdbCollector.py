from urllib.request import Request, urlopen
import urllib.parse
import base64
import json
import os, sys
import xml.etree.ElementTree as ET
from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBClientError, InfluxDBServerError
import time
from urllib.error import HTTPError
import configparser
from requests.exceptions import ConnectionError

class plexInfluxdbCollector():

    def __init__(self):

        self.config = configManager()

        self.servers = self.config.plex_servers
        self.output = self.config.output
        self.token = None
        self._report_combined_streams = True
        self.delay = self.config.delay
        self.influx_client = InfluxDBClient(self.config.influx_address, self.config.influx_port, database=self.config.influx_database)
        self._get_auth_token(self.config.plex_user, self.config.plex_password)



    def _get_auth_token(self, username, password):
        """
        Make a reqest to plex.tv to get an authentication token for future requests
        :param username: Plex Username
        :param password: Plex Password
        :return:
        """

        print('Getting Auth Token For User {}'.format(username))

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
            else:
                print('Maybe this will help:')
                print(e)
            sys.exit(1)


        output = json.loads(result.decode('utf-8'))

        # Make sure we actually got a token back
        if 'authToken' in output['user']:
            self.token = output['user']['authToken']
        else:
            print('Something Broke \n We got a valid response but for some reason there\'s no auth token')
            sys.exit(1)

        print('Successfully Retrieved Auth Token Of: {}'.format(self.token))

    def _set_default_headers(self, req):
        """
        Sets the default headers need for a request
        :param req:
        :return:
        """

        headers = {
            'X-Plex-Client-Identifier': 'Plex InfluxDB Collector',
            'X-Plex-Product': 'Plex InfluxDB Collector',
            'X-Plex-Version': '1',
            'X-Plex-Token': self.token
        }

        for k, v in headers.items():
            if k == 'X-Plex-Token' and not self.token:  # Don't add token if we don't have it yet
                continue

            req.add_header(k,v)

        return req

    def get_active_streams(self):
        """

        :param server:
        :return:
        """

        active_streams = {}

        for server in self.servers:
            req = Request('http://{}:32400/status/sessions'.format(server))
            self._set_default_headers(req)

            # TODO figured out which exceptions to catch here
            result = urlopen(req).read().decode('utf-8')

            streams = ET.fromstring(result)


            active_streams[server] = streams

        self._process_active_streams(active_streams)

    def _process_active_streams(self, stream_data):
        """
        Take an object of stream data and create Influx JSON data
        :param stream_data:
        :return:
        """
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

                # Figure Out Media Type
                if stream.attrib['type'] == 'movie':
                    media_type = 'Movie'
                elif stream.attrib['type'] == 'episode':
                    media_type = 'TV Show'
                elif stream.attrib['type'] == 'track':
                    media_type = 'Music'
                else:
                    media_type = 'Unknown'

                # Build the title. TV and Music Have a root title plus episode/track name.  Movies don't
                full_title = ""
                if 'grandparentTitle' in stream.attrib:
                    full_title = stream.attrib['grandparentTitle'] + ' - ' + stream.attrib['title']
                else:
                    full_title = stream.attrib['title']

                resolution = 'N/A'
                if media_type != 'Music':
                    resolution = stream.find('Media').attrib['videoResolution'] + 'p'
                else:
                    resolution = stream.find('Media').attrib['bitrate'] + 'Kbps'

                playing_points = [
                    {
                        'measurement': 'now_playing',
                        'fields': {
                            'stream_title': full_title,
                            'player': stream.find('Player').attrib['title'],
                            'user': stream.find('User').attrib['title'],
                            'resolution': resolution,
                            'media_type': media_type
                        },
                        'tags': {
                            'host': host,
                            'player_address': stream.find('Player').attrib['address']
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
            req = Request('http://{}:32400/library/sections'.format(server))
            req = self._set_default_headers(req)

            result = urlopen(req).read().decode('utf-8')

            libs = ET.fromstring(result)

            host_libs = []
            if len(libs) > 0:
                for i in range(1, len(libs) + 1):
                    req = Request('http://{}:32400/library/sections/{}/all'.format(server, i))
                    req = self._set_default_headers(req)
                    result = urlopen(req).read().decode('utf-8')
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
        try:
            self.influx_client.write_points(json_data)
        except (InfluxDBClientError, ConnectionError, InfluxDBServerError) as e:
            if hasattr(e, 'code') and e.code == 404:
                print('Database {} Does Not Exist.  Attempting To Create')
                # TODO Grab exception here
                self.influx_client.create_database(self.config.influx_database)
                self.influx_client.write_points(json_data)
                return
            print('ERROR: Failed To Write To InfluxDB')
            print(e)


    def run(self):

        print('Starting Monitoring Loop \n ')
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
        print('Configuration Successfully Loaded')

    def _load_config_values(self):

        # General
        self.delay = self.config['GENERAL'].getint('Delay', fallback=2)
        self.output = self.config['GENERAL'].getboolean('Output', fallback=True)

        # InfluxDB
        self.influx_address = self.config['INFLUXDB']['Address']
        self.influx_port = self.config['INFLUXDB'].getint('Port', fallback=8086)
        self.influx_database = self.config['INFLUXDB'].get('Database', fallback='plex_data')

        # Plex
        self.plex_user = self.config['PLEX']['Username']
        self.plex_password = self.config['PLEX']['Password']
        servers = len(self.config['PLEX']['Servers'])


        if servers:
            self.plex_servers = self.config['PLEX']['Servers'].split(',')
        else:
            print('ERROR: No Plex Servers Provided.  Aborting')
            sys.exit(1)


def main():

    collector = plexInfluxdbCollector()
    collector.run()



if __name__ == '__main__':
    main()