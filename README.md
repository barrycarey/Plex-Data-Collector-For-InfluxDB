**Plex Data Collector For InfluxDB**
------------------------------

![Screenshot](https://puu.sh/tarSA/aea875c453.png)

This is a tool for collecting some basic info about your Plex server and sending it to InfluxDB.  This is ideal for displaying Plex specific information in a tool such as Grafana. 

## Configuration within config.ini

#### GENERAL
|Key            |Description                                                                                                         |
|:--------------|:-------------------------------------------------------------------------------------------------------------------|
|Delay          |Delay between updating metrics                                                                                      |
|Output         |Write console output while tool is running                                                                          |
#### INFLUXDB
|Key            |Description                                                                                                         |
|:--------------|:-------------------------------------------------------------------------------------------------------------------|
|Address        |Delay between updating metrics                                                                                      |
|Port           |InfluxDB port to connect to.  8086 in most cases                                                                    |
|Database       |Database to write collected stats to                                                                                |
|Username       |User that has access to the database                                                                                |
|Password       |Password for above user                                                                                             |
#### PLEX
|Key            |Description                                                                                                         |
|:--------------|:-------------------------------------------------------------------------------------------------------------------|
|Username       |Plex username                                                                                                       |
|Password       |Plex Password                                                                                                       |
|Servers        |A comma separated list of servers you wish to pull data from.                                                       |
#### LOGGING
|Key            |Description                                                                                                         |
|:--------------|:-------------------------------------------------------------------------------------------------------------------|
|Enable         |Output logging messages to provided log file                                                                        |
|Level          |Minimum type of message to log.  Valid options are: critical, error, warning, info, debug                           |
|LogFile        |File to log messages to.  Can be relative or absolute path                                                          |
|CensorLogs     |Censor certain things like server names and IP addresses from logs                                                  |


**Usage**

Enter your desired information in config.ini and run plexInfluxdbCollector.py

Optionally, you can specify the --config argument to load the config file from a different location.  


***Requirements***

Python 3+

You will need the influxdb library installed to use this - [Found Here](https://github.com/influxdata/influxdb-python)

