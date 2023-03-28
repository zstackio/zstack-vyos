#!/bin/vbash
source /opt/vyatta/etc/functions/script-template

configure

load /opt/vyatta/etc/config/config.boot

commit

exit
