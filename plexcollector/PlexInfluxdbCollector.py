import base64
import json
import sys
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBClientError, InfluxDBServerError
from plexapi.server import PlexServer
from requests.exceptions import ConnectionError

# TODO Build word blacklist for logs.
# TODO - Cleanup server URL handling
# TODO - Add proper log filter instead of shim method
# TODO - Redo package structure
from plexcollector.config import config, log


class PlexInfluxdbCollector:

    def __init__(self):

        self.server_addresses = config.plex_server_addresses
        self.plex_servers = []
        self.logger = log
        self.token = None
        self.active_streams = {}  # Store active streams so we can track duration
        self.delay = config.delay
        # TODO - Move to method that validates connection
        self.influx_client = InfluxDBClient(
            config.influx_address,
            config.influx_port,
            database=config.influx_database,
            ssl=config.influx_ssl,
            verify_ssl=config.influx_verify_ssl,
            username=config.influx_user,
            password=config.influx_password

        )

        self._get_auth_token(config.plex_user, config.plex_password)
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

    def _get_auth_token(self, username, password):
        """
        Make a reqest to plex.tv to get an authentication token for future requests
        :param username: Plex Username
        :param password: Plex Password
        :return:
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
            self.token = output['user']['authToken']
        else:
            print('Something Broke \n We got a valid response but for some reason there\'s no auth token')
            sys.exit(1)

        log.info('Successfully Retrieved Auth Token Of: {}'.format(self.token))

    def _set_default_headers(self, req):
        """
        Sets the default headers need for a request
        :param req:
        :return:
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

                session_id = self._get_session_id(stream)
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


                log.debug('Title: {}'.format(full_title))
                log.debug('Media Type: {}'.format(media_type))
                log.debug('Session ID: {}'.format(session_id))
                log.debug('Resolution: {}'.format(resolution))
                log.debug('Duration: {}'.format(str(time.time() - start_time)))

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

            # TODO - Redo how we name servers so we don't have to access private var
            lib_data[server._baseurl] = host_libs

        self._process_library_data(lib_data)

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
        log.debug(json_data)

        try:
            self.influx_client.write_points(json_data)
        except (InfluxDBClientError, ConnectionError, InfluxDBServerError) as e:
            if hasattr(e, 'code') and e.code == 404:

                log.error('Database {} Does Not Exist.  Attempting To Create')

                # TODO Grab exception here
                self.influx_client.create_database(config.influx_database)
                self.influx_client.write_points(json_data)

                return

            log.error('Failed to write data to InfluxDB')

        log.debug('Written To Influx: {}'.format(json_data))

    def run(self):

        log.info('Starting Monitoring Loop')
        while True:
            self.get_library_data()
            self.get_active_streams()
            time.sleep(self.delay)





