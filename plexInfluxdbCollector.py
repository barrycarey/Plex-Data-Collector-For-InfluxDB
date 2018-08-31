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
import argparse
import re
from http.client import RemoteDisconnected

from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBClientError, InfluxDBServerError
from plexapi.server import PlexServer
from requests.exceptions import ConnectionError


#TODO Build word blacklist for logs.
# TODO - Cleanup server URL handling
# TODO - Add proper log filter instead of shim method
from configmanager import configManager


class plexInfluxdbCollector():

    def __init__(self, silent, config=None):

        self.config = configManager(silent, config=config)

        self.server_addresses = self.config.plex_server_addresses
        self.plex_servers = []
        self.output = self.config.output
        self.token = None
        self.logger = None
        self.active_streams = {}  # Store active streams so we can track duration
        self._report_combined_streams = True # TODO Move to config
        self.delay = self.config.delay
        self.influx_client = InfluxDBClient(
            self.config.influx_address,
            self.config.influx_port,
            database=self.config.influx_database,
            ssl=self.config.influx_ssl,
            verify_ssl=self.config.influx_verify_ssl,
            username=self.config.influx_user,
            password=self.config.influx_password

        )
        self._set_logging()
        self._get_auth_token(self.config.plex_user, self.config.plex_password)
        self._build_server_list()

    def _build_server_list(self):
        """
        Build a list of plexapi objects from the servers provided in the config
        :return:
        """
        for server in self.server_addresses:
            base_url = 'http://{}:32400'.format(server)
            api_conn = PlexServer(base_url, self.token)
            # TODO - Connection exectpion
            self.plex_servers.append(api_conn)

    def _set_logging(self):
        """
        Create the logger object if enabled in the config
        :return: None
        """

        if self.config.logging:
            if self.output:
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

        if self.output and self.config.valid_log_levels[level.upper()] >= self.config.logging_print_threshold:
            print(msg)

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

        msg = str(msg)

        if not self.config.logging_censor:
            return msg

        msg = msg.replace(self.config.plex_user, '********')
        if self.token:
            msg = msg.replace(self.token, '********')

        # Remove server addresses
        for server in self.server_addresses:
            msg = msg.replace(server, '*******')

        # Remove IP addresses
        for match in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", msg):
            msg = msg.replace(match, '***.***.***.***')

        return msg

    def _get_auth_token(self, username, password):
        """
        Make a reqest to plex.tv to get an authentication token for future requests
        :param username: Plex Username
        :param password: Plex Password
        :return:
        """

        self.send_log('Getting Auth Token For User {}'.format(username), 'info')

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

        self.send_log('Successfully Retrieved Auth Token Of: {}'.format(self.token), 'info')

    def _set_default_headers(self, req):
        """
        Sets the default headers need for a request
        :param req:
        :return:
        """

        self.send_log('Adding Request Headers', 'debug')

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

        self.send_log('Attempting to get active sessions', 'info')
        active_streams = {}
        for server in self.plex_servers:
            active_sessions = server.sessions()
            active_streams[server._baseurl] = active_sessions

        self._process_active_streams(active_streams)

    def _get_session_id(self, stream):
        """
        Find a unique key to identify the stream.  In most cases it will be the sessionKey.  If this does not exist,
        fall back to the TranscodeSession key.
        :param stream: XML object of the stream
        :return:
        """

        if hasattr(stream, 'sessionKey'):
            return stream.sessionKey

        session = stream.find('Session')

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
        session_ids = []  # Active Session IDs for this run

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
                #session_id = stream.sessionKey
                session_ids.append(session_id)

                player = stream.players[0]
                user = stream.usernames[0]

                if session_id in self.active_streams:
                    start_time = self.active_streams[session_id]['start_time']
                else:
                    start_time = time.time()
                    self.active_streams[session_id] = {}
                    self.active_streams[session_id]['start_time'] = start_time

                if stream.type == 'movie':
                    media_type = 'Movie'
                elif stream.type == 'episode':
                    media_type = 'TV Show'
                elif stream.type == 'track':
                    media_type = 'Music'
                else:
                    media_type = 'Unknown'

                # Build the title. TV and Music Have a root title plus episode/track name.  Movies don't
                if hasattr(stream, 'grandparentTitle'):
                    full_title = stream.grandparentTitle + ' - ' + stream.title
                else:
                    full_title = stream.title

                if media_type != 'Music':
                    resolution = stream.media[0].videoResolution
                else:
                    resolution = stream.media[0].bitrate + 'Kbps'


                self.send_log('Title: {}'.format(full_title), 'debug')
                self.send_log('Media Type: {}'.format(media_type), 'debug')
                self.send_log('Session ID: {}'.format(session_id), 'debug')
                self.send_log('Resolution: {}'.format(resolution), 'debug')
                self.send_log('Duration: {}'.format(str(time.time() - start_time)), 'debug')

                playing_points = [
                    {
                        'measurement': 'now_playing',
                        'fields': {
                            'stream_title': full_title,
                            'player': player.title,
                            'state': player.state,
                            'user': user,
                            'resolution': resolution,
                            'media_type': media_type,
                            'duration': time.time() - start_time
                        },
                        'tags': {
                            'host': host,
                            'player_address': player.address,
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
            self._remove_dead_streams(session_ids)

    def _remove_dead_streams(self, current_streams):
        """
        Go through the stored list of active streams and remove any that are no longer active
        :param current_streams: List of currently active streams from last API call
        :return:
        """
        remove_keys = []
        for id, data in self.active_streams.items():
            if id not in current_streams:
                remove_keys.append(id)
        for key in remove_keys:
            self.active_streams.pop(key)

    def get_library_data_new(self):

        lib_data = {}

        for server in self.plex_servers:
            libs = server.library.sections()
            self.send_log('We found {} libraries for server {}'.format(str(len(libs)), server), 'info')
            host_libs = []
            for lib in libs:
                host_lib = {
                    'name': lib.title,
                    'items': len(lib.search())
                }

                if lib.title == 'TV Shows':
                    seasons = 0
                    episodes = 0
                    shows = lib.search()
                    for show in shows:
                        seasons += len(show.seasons())
                        episodes += len(show.episodes())
                    host_lib['episodes'] = episodes
                    host_lib['seasons'] = seasons

                host_libs.append(host_lib)

            # TODO - Redo how we name servers
            lib_data[server._baseurl] = host_libs

        self._process_library_data(lib_data)

    def _process_library_data(self, lib_data):
        """
        Breakdown the provided library data and format for InfluxDB
        """

        self.send_log('Processing Library Data', 'info')

        for host, data in lib_data.items():
            for lib in data:
                fields = {
                    'items': lib['items'],
                }
                for c in ['episodes', 'seasons']:
                    if c in lib:
                        fields[c] = lib[c]
                lib_points = [
                    {
                        'measurement': 'libraries',
                        'fields': fields,
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
        self.send_log(json_data, 'debug')

        try:
            self.influx_client.write_points(json_data)
        except (InfluxDBClientError, ConnectionError, InfluxDBServerError) as e:
            if hasattr(e, 'code') and e.code == 404:

                self.send_log('Database {} Does Not Exist.  Attempting To Create', 'error')

                # TODO Grab exception here
                self.influx_client.create_database(self.config.influx_database)
                self.influx_client.write_points(json_data)

                return

            self.send_log('Failed to write data to InfluxDB', 'error')

        self.send_log('Written To Influx: {}'.format(json_data), 'debug')

    def run(self):

        self.send_log('Starting Monitoring Loop', 'info')

        while True:
            self.get_library_data_new()
            self.get_active_streams()
            time.sleep(self.delay)





def main():

    parser = argparse.ArgumentParser(description="A tool to send Plex statistics to InfluxDB")
    parser.add_argument('--config', default='config.ini', dest='config', help='Specify a custom location for the config file')
    parser.add_argument('--silent', action='store_true', help='Surpress All Output, regardless of config settings')
    args = parser.parse_args()
    collector = plexInfluxdbCollector(args.silent, config=args.config)
    collector.run()


if __name__ == '__main__':
    main()
