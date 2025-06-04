#!/bin/bash
lftp -u if0_37766858,9340Camada ftpupload.net << EOF
cd /matthew.trevino.today/htdocs/
mirror -R /home/flintx/hyde-site/public/ .
bye
EOF
