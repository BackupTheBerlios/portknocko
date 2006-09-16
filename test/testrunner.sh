#!/bin/bash

function include() {
	testcase=$(cat $1)
	eval "$testcase"
}

######## TESTRUNNER #########

include "scripts/lib.sh"

if [ -z $1 ]; then 
    echo "usage: $0 <testfile>"
    exit 1
fi

digest_file="cache/digest.txt"
result_file="cache/result.txt"

init $result_file $digest_file

include $1

python py/asserter.py $result_file
