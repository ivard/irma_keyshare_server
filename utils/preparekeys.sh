#!/bin/bash

dir=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
maindir=$dir/../src/main/resources

# Generate JWT signing keys
$dir/keygen.sh $maindir/sk $maindir/pk
rm $maindir/sk.pem 2> /dev/null # Not needed

# Recovery key
# Execute in irma_configuration/<scheme_to_enable_encryption>
# openssl genpkey -algorithm RSA -out recovery_private_key.pem -pkeyopt rsa_keygen_bits:2048
# openssl pkcs8 -topk8 -nocrypt -in recovery_private_key.pem -inform PEM -out recovery_private_key.der -outform DER
# openssl rsa -in recovery_private_key.pem -pubout -outform DER -out recovery_public_key.der
