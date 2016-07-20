[main]
# Enable debug: true|false 
debug = False
# For token creation see
# https://www.dropbox.com/developers-v1/business
token = YOUR_ACCESS_TOKEN_HERE
# Only grab events in the past hour (3600s)
timespan = 3600
# Known protocols: udp, tcp, tls
protocol = tls
# GELF collector host
host = graylog.example.com
# GELF collector port
port = 12201
# Trusted CA store (only used for TLS connections)
tls_cafile = /etc/ssl/certs/ca-certificates.crt
# Source label for Graylog
source_label = Dropbox-audit
