# IRMA keyshare server

The IRMA keyshare server is a server that performs a share of the IRMA cryptography, so as to better protect the keys on the phone. It is meant to work together with the [IRMA mobile app](https://github.com/privacybydesign/irma_mobile).

## Configuring the server

To configure the server you need to setup both `irma_configuration`, a MySQL database, some JWT keys and a config file.

### irma_configuration

Download or link the `irma_configuration` project to `src/main/resources/`. If both projects are in the same directory the following should work:

    ln -s ../../../../irma_configuration src/main/resources/

Note that for the irmago tests, you should use the `irma_configuration` folder provided with [irmago](https://github.com/privacybydesign/irmago/tree/master/testdata/irma_configuration)

### General configuration

You can configure the server at `src/main/resources/config.json`. In the same directory a sample configuration file called `config.sample.json` is included, showing all options, their defaults, and what they mean. The sample configuration file should work out of the box for the irmago unit tests (provided you have MailCatcher installed, see below).

### Configuring the database

Create a MySQL database and configure its credentials in:

    src/test/resources/jetty-env.xml

Populate the database with the `database.sql` file with a command like this (assuming user `irma`, password `irma` and database `irma_keyshare`):

    mysql -uirma -pirma irma_keyshare < ./src/main/resources/database.sql

### Generating JWT keys

Run the following script:

    ./utils/preparekeys.sh

This script generates a keypair (`pk.der` and `sk.der`) and copies it to `src/main/resources`. You'll need to copy `pk.der` to your local `irma_api_server` with a command like this:

    cp ./src/main/resources/pk.der ../irma_api_server/src/main/resources/test-kss.der

The `test-` in `test-kss.der` refers to the name of the scheme manager. Rename this appropriately.

### Handling e-mail during development

For development, it can be useful to 'catch' every e-mail that is sent by the server. One can use an application like [MailCatcher](https://mailcatcher.me/) for this. The example configuration file already contains a working config for MaiCatcher.

## Running the server

The gradle build file should take care of the dependencies. To run the server in development mode simply call:

    gradle appRun --no-daemon

## Server API

The following describes the API offered by the server to an IRMA client.

### Register

Before the server can be used for any IRMA protocols, a client needs to register itself with the server.

<!-- vim: set ts=4 sw=4: -->
