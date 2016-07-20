# Dropbox-gelf

A Dropbox audit log to Graylog injector, powered by pyGELF.

## Overview

Dropbox Business API (v1) offers [an endpoint](https://www.dropbox.com/developers-v1/business/docs#log-get-events) to retrieve audit logs for a Dropbox Business account.

This python3 script provides a log injector to fetch events from Dropbox API and send them to Graylog via GELF (UDP, TCP or TLS).


## Dropbox setup

You have to first setup a custom new application in your Dropbox business account. You can read [Dropbox doc](https://www.dropbox.com/developers-v1/business) on how to do it.

Then, an access token can be generated in the "Generated Access Token" section of your console. This script needs a token with "Team auditing" permission in order to fetch audit logs.

## Script setup

The `dropbox-gelf.conf.ex` sample configuration file in this repository has to be customized for your Dropbox account and Graylog setup. Make sure it is *NOT* world-readable (as it contains a private token).

```
cp dropbox-gelf.conf.ex dropbox-gelf.ini
editor dropbox-gelf.ini
sudo chown nobody dropbox-gelf.ini
sudo chmod 0700 dropbox-gelf.ini
```

Then, you only need to create a python3 virtualenv for it and setup a cronjob.

```
pyvenv dbgelf-venv
source dbgelf-venv/bin/activate
pip3 install -r requirements.txt
sudo cp dropbox-gelf.cron /etc/cron.d/dropbox-gelf
sudo editor /etc/cron.d/dropbox-gelf
```

A cronjob template is provided in `dropbox-gelf.cron`, running the script from `/opt/dropbox-gelf` as user `nobody` every 60 minutes. Please make sure your cron interval and `timespan` parameter match, otherwise *you will lose audit logs*. 


### Dropbox Business API v2 update (2016-07-20)
Dropbox has not made available yet an audit endpoint for the v2 API. The existing v2 documentation suggests to keep using the v1 endpoint (/1/team/log/get_events). Ref: https://www.dropbox.com/developers/reference/migration-guide
