import argparse

from plexcollector.PlexInfluxdbCollector import PlexInfluxdbCollector

parser = argparse.ArgumentParser(description="A tool to send Plex statistics to InfluxDB")
parser.add_argument('--singlerun', action='store_true', help='Only runs through once, does not keep monitoring')
args = parser.parse_args()
collector = PlexInfluxdbCollector(single_run=args.singlerun)
collector.run()

