#!/usr/bin/env bash
# Simplified version of: https://github.com/h12w/gosweep/blob/master/gosweep.sh
# by Wáng Hǎiliàng
DIR_SOURCE="$(find . -maxdepth 10 -type f -not -path '*/vendor*' -name '*.go' | xargs -I {} dirname {} | sort | uniq)"

# If you want to test in combination with the -race flag on you have to use the atomic mode:
# echo "mode: atomic" > profile.cov
echo "mode: count" > profile.cov

all_tests_passed=true
# Run test coverage on each subdirectories and merge the coverage profile
for dir in ${DIR_SOURCE};
do
    # change to -covermode=atomic if you want to run in combination with -race:
    go test -covermode=count -coverprofile=$dir/profile.tmp $dir
    if [ $? -ne 0 ]; then
        all_tests_passed=false
    fi
    if [ -f $dir/profile.tmp ]
    then
        cat $dir/profile.tmp | tail -n +2 >> profile.cov
        rm $dir/profile.tmp
    fi
done

if [[ $all_tests_passed = true ]]; then
    exit 0;
else
    exit 1;
fi