IPSEC_CHARON_PID=/var/run/charon.pid

sudo ipsec stop

if [ -e $IPSEC_CHARON_PID ]
then
    echo "kill charon" >&2
    charonpid=`cat $IPSEC_CHARON_PID`
    if [ -n $charonpid ]
    then
        kill $charonpid 2>/dev/null
        loop=5
        while [ $loop -gt 0 ] ; do
            kill -0 $charonpid 2>/dev/null || break
            sleep 1
            loop=$(($loop - 1))
        done
        if [ $loop -eq 0 ]
        then
            kill -KILL $charonpid 2>/dev/null
            rm -f $IPSEC_CHARON_PID
        fi
    fi
fi

sudo ipsec start