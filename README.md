**Plex Data Collector For InfluxDB**
------------------------------

![Screenshot](https://puu.sh/tarSA/aea875c453.png)

This is a tool for collecting some basic info about your Plex server and sending it to InfluxDB.  This is ideal for displaying Plex specific information in a tool such as Grafana. 

## Configuration within config.ini

#### GENERAL
|Key            |Description                                                                                                         |
|:--------------|:-------------------------------------------------------------------------------------------------------------------|
|Delay          |Delay between updating metrics                                                                                      |
|ReportCombined |When using multiple servers report total streams over all servers                                                   |
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
|Level          |Minimum type of message to log.  Valid options are: critical, error, warning, info, debug                           |


**Usage**

Enter your desired information in config.ini and run plexInfluxdbCollector.py

***Requirements***

Python 3+

You will need the influxdb library installed to use this - [Found Here](https://github.com/influxdata/influxdb-python)

