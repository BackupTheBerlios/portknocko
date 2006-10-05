#!/bin/bash

if [ -z $1 ]; then
	echo "usage: $0 <loop_nro>"
	exit 1
fi

for ((  i = 0 ;  i < $1;  i++  ))
do
	./testrunner.sh all.test
done

