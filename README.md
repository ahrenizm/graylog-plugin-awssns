Twilio SMS Plugin for Graylog
=============================

[![Github Downloads](https://img.shields.io/github/downloads/graylog-labs/graylog-plugin-twiliosms/total.svg)](https://github.com/graylog-labs/graylog-plugin-twiliosms/releases)
[![GitHub Release](https://img.shields.io/github/release/graylog-labs/graylog-plugin-twiliosms.svg)](https://github.com/graylog-labs/graylog-plugin-twiliosms/releases)
[![Build Status](https://travis-ci.org/graylog-labs/graylog-plugin-twiliosms.svg)](https://travis-ci.org/graylog-labs/graylog-plugin-twiliosms)

An alarm callback plugin for integrating the [Twilio SMS API](https://www.twilio.com/sms) into [Graylog](https://www.graylog.org/).

**Required Graylog version:** 2.0.0 and later

## Installation

[Download the plugin](https://github.com/graylog-labs/graylog-plugin-twiliosms/releases)
and place the `.jar` file in your Graylog plugin directory. The plugin directory
is the `plugins/` folder relative from your `graylog-server` directory by default
and can be configured in your `graylog.conf` file.

Restart `graylog-server` and you are done.

## Build

This project is using Maven 3 and requires Java 8 or higher.

You can build the plugin (JAR) with `mvn package`.

DEB and RPM packages can be built with `mvn jdeb:jdeb` and `mvn rpm:rpm` respectively.

## Plugin Release

We are using the maven release plugin:

```
$ mvn release:prepare
[...]
$ mvn release:perform
```

This sets the version numbers, creates a tag and pushes to GitHub. Travis CI will build the release artifacts and upload to GitHub automatically.
