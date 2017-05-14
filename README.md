# IRMA keyshare server

** NOTE: Don't use this! This project is work in progress and not yet finished. **

The IRMA keyshare server is a server that performs a share of the IRMA cryptography, so as to better protect the keys on the phone. It is meant to work together with the [card emulator app](https://github.com/credentials/irma_android_cardemu).

## Configuring the server

To configure the service you need to setup both irma_configuration and a config file.

### irma_configuration

Download or link the `irma_configuration` project to `src/main/resources/`. If both projects are in the same directory the following should work:

    ln -s ../../../../irma_configuration src/main/resources/

### General configuration

You can configure the server at `src/main/resources/config.json`. In the same directory a sample configuration file called `config.sample.json` is included, showing all options, their defaults, and what they mean.

## Running the server

The gradle build file should take care the dependencies. To run the server in development mode simply call:

    gradle appRun

## Server API

The following describes the API offered by the server to an IRMA client.

### Register

Before the server can used for any IRMA protocols, a client needs to register itself with the server.
