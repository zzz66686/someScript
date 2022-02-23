#!/bin/sh

#ps |  grep "gdbserver" | grep -v "grep" | awk '{print $4}'

gdbserver_id=`pidof gdbserver_armle`
kill $gdbserver_id

target_id=`pidof $1`
./gdbserver_armle --attach 0.0.0.0:23946 $target_id