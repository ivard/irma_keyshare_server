# IRMA keyshare server

**Fork of Privacy By Design's IRMA keyshare server!**
**For original version go to https://github.com/privacybydesign/irma_keyshare_server**

The IRMA keyshare server performs a share of the IRMA cryptography during IRMA sessions, in order to better protect the IRMA secret key on the phone. It does this by keeping a part of the IRMA user's secret key, and using this to cooperate in the IRMA protocol if and only if the user enters the correct PIN code. It is meant to work together with the [IRMA mobile app](https://github.com/privacybydesign/irma_mobile). In addition, this server exposes an API that is used by the [IRMA keyshare webclient](https://github.com/privacybydesign/irma_keyshare_webclient), on which the user can administer her account at this server.

The keyshare protocol between the IRMA user and this server is documented [here](https://credentials.github.io/protocols/keyshare-protocol/).

## Configuring the server

To configure the server you need to setup both `irma_configuration`, a MySQL database, some JWT keys and a config file.

### irma_configuration

The credential and issuer descriptions and issuer public keys - that is, the *scheme manager* information - are expected in a subdirectory called `irma_configuration` within `src/main/resources`. There are several options:

* You can use our [`irma-demo`](https://github.com/privacybydesign/irma-demo-schememanager) scheme manager (which includes issuer private keys) for experimenting,
* You can use our [`pbdf`](https://github.com/privacybydesign/pbdf-schememanager) if you want to verify attributes issued by the [Privacy by Design Foundation](https://privacybydesign.foundation/issuance),
* you can create your own scheme manager containing your own issuers and credential types.

For example, in the first case, you would `cd` to your configuration directory, and do

    mkdir irma_configuration 2>/dev/null
    cd irma_configuration
    git clone https://github.com/privacybydesign/irma-demo-schememanager irma-demo

For more information, see the [README.md of the `irma-demo` scheme manager](https://github.com/privacybydesign/irma-demo-schememanager).

Note that for the [`irmago`](https://github.com/privacybydesign/irmago) tests, you should use the `irma_configuration` folder provided with [irmago](https://github.com/privacybydesign/irmago/tree/master/testdata/irma_configuration)

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
