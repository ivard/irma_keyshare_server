#!/bin/bash

dir=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
maindir=$dir/../src/main/resources

# Generate JWT signing keys
$dir/keygen.sh $maindir/sk $maindir/pk
rm $maindir/sk.pem 2> /dev/null # Not needed
