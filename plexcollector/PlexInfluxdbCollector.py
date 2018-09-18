import base64
import json
import sys
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import requests
from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBClientError, InfluxDBServerError
from plexapi.server import PlexServer
from requests import ConnectTimeout

from plexcollector.common import log
from plexcollector.config import config

# TODO - Update readme for PMS SSL
class PlexInfluxdbCollector:

    def __init__(self, single_run=False):

        self.server_addresses = config.plex_server_addresses
        self.plex_servers = []
        self.logger = log
        self.token = None
        self.single_run = single_run
        self.active_streams = {}  # Store active streams so we can track duration
        self.delay = config.delay
        self.influx_client = self._get_influx_connection()

        # Prevents console spam if verify ssl is disabled
        if not config.plex_verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self._build_server_list()

    def _build_server_list(self):
        """
        Build a list of plexapi objects from the servers provided in the config
        :return:
        """
        for server in self.server_addresses:
            base_url = '{}://{}:32400'.format(config.conn_security, server)
            session = requests.Session()
            session.verify = config.plex_verify_ssl
            api_conn = PlexServer(base_url, self.get_auth_token(config.plex_user, config.plex_password), session=session)
            self.plex_servers.append(api_conn)

    def _get_influx_connection(self):
        """
        Create an InfluxDB connection and test to make sure it works.
        We test with the get all users command.  If the address is bad it fails
        with a 404.  If the user doesn't have permission it fails with 401
        :return:
        """
        # TODO - Check what permissions are actually needed to make this work
        influx = InfluxDBClient(
            config.influx_address,
            config.influx_port,
            database=config.influx_database,
            ssl=config.influx_ssl,
            verify_ssl=config.influx_verify_ssl,
            username=config.influx_user,
            password=config.influx_password,
            timeout=5
        )
        try:
            log.debug('Testing connection to InfluxDb using provided credentials')
            influx.get_list_users() # TODO - Find better way to test connection and permissions
            log.debug('Successful connection to InfluxDb')
        except (ConnectTimeout, InfluxDBClientError) as e:
            if isinstance(e, ConnectTimeout):
                log.critical('Unable to connect to InfluxDB at the provided address (%s)', config.influx_address)
            elif e.code == 401:
                log.critical('Unable to connect to InfluxDB with provided credentials')

            sys.exit(1)

        return influx

    def get_auth_token(self, username, password):
        """
        Make a reqest to plex.tv to get an authentication token for future requests
        :param username: Plex Username
        :param password: Plex Password
        :return: str
        """

        log.info('Getting Auth Token For User {}'.format(username))

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
                log.error('Failed to get token due to bad username/password')
            else:
                print('Maybe this will help:')
                print(e)
                log.error('Failed to get authentication token.  No idea why')
            sys.exit(1)

        output = json.loads(result.decode('utf-8'))

        # Make sure we actually got a token back
        if 'authToken' in output['user']:
            log.debug('Successfully Retrieved Auth Token')
            return output['user']['authToken']
        else:
            print('Something Broke \n We got a valid response but for some reason there\'s no auth token')
            sys.exit(1)



    def _set_default_headers(self, req):
        """
        Sets the default headers need for a request
        :param req:
        :return: request
        """

        log.debug('Adding Request Headers')

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

        log.info('Attempting to get active sessions')
        active_streams = {}
        for server in self.plex_servers:
            active_sessions = server.sessions()
            active_streams[server._baseurl] = active_sessions

        self._process_active_streams(active_streams)

    def _process_active_streams(self, stream_data):
        """
        Take an object of stream data and create Influx JSON data
        :param stream_data:
        :return:
        """

        log.info('Processing Active Streams')

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
                player = stream.players[0]
                user = stream.usernames[0]
                session_id = stream.session[0].id
                transcode = stream.transcodeSessions if stream.transcodeSessions else None
                session_ids.append(session_id)

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
                    resolution = str(stream.media[0].bitrate) + 'Kbps'

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
                            'playback': 'transcode' if transcode else 'direct',
                            'duration': time.time() - start_time,
                        },
                        'tags': {
                            'host': host,
                            'player_address': player.address,
                            'session_id': session_id
                        }
                    }
                ]

                self.write_influx_data(playing_points)

        if config.report_combined:
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

    def get_library_data(self):

        lib_data = {}

        for server in self.plex_servers:
            libs = server.library.sections()
            log.info('We found {} libraries for server {}'.format(str(len(libs)), server))
            host_libs = []
            for lib in libs:
                log.info('Adding data for library %s', lib.title)
                host_lib = {
                    'name': lib.title,
                    'items': len(lib.search())
                }

                if lib.title == 'TV Shows':
                    log.info('Processing TV Shows.  This can take awhile for large libraries')
                    seasons = 0
                    episodes = 0
                    shows = lib.search()
                    for show in shows:
                        log.debug('Checking TV Show: %s', show.title)
                        seasons += len(show.seasons())
                        episodes += len(show.episodes())
                    host_lib['episodes'] = episodes
                    host_lib['seasons'] = seasons

                host_libs.append(host_lib)

            lib_data[server._baseurl] = host_libs

        self._process_library_data(lib_data)

    def get_recently_added(self):
        """
        Build list of recently added
        :return:
        """

        results = []

        for server in self.plex_servers:
            recent_list = []

            for section in server.library.sections():
                recent_list += section.recentlyAdded(maxresults=10)

            for item in recent_list:
                data = {
                    'measurement': 'recently_added',
                    'fields': {
                        'media_type': item.type.title(),
                        'added_at': item.addedAt.strftime('%Y-%m-%dT%H:%M:%SZ'),
                    },
                    'tags': {
                        'host': server._baseurl
                    }
                }

                if hasattr(item, 'grandparentTitle'):
                    data['fields']['title'] = item.grandparentTitle + ' - ' + item.title
                else:
                    data['fields']['title'] = item.title


                self.write_influx_data([data])


    def _process_library_data(self, lib_data):
        """
        Breakdown the provided library data and format for InfluxDB
        """

        log.info('Processing Library Data')

        for host, data in lib_data.items():
            for lib in data:
                fields = {
                    'items': lib['items'],
                }
                for key in ['episodes', 'seasons']:
                    if key in lib:
                        fields[key] = lib[key]
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
        log.debug(json_data)

        try:
            self.influx_client.write_points(json_data)
        except (InfluxDBClientError, ConnectionError, InfluxDBServerError) as e:
            if hasattr(e, 'code') and e.code == 404:
                log.error('Database {} Does Not Exist.  Attempting To Create')
                self.influx_client.create_database(config.influx_database)
                self.influx_client.write_points(json_data)
                return
            log.error('Failed to write data to InfluxDB')

        log.debug('Written To Influx: {}'.format(json_data))

    def run(self):

        log.info('Starting Monitoring Loop')
        while True:
            self.get_recently_added()
            self.get_library_data()
            self.get_active_streams()
            if self.single_run:
                return
            time.sleep(self.delay)
