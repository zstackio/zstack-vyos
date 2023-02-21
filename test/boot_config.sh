#!/bin/vbash
source /opt/vyatta/etc/functions/script-template

configure

load /config/config.boot

commit

exit
