# Jenkins Bouncy Castle API Plugin

 This plugin provides an stable API to Bouncy Castle related tasks. Plugins using Bouncy Castle should depend on this plugin and not directly on Bouncy Castle. See also this [plugin's wiki page][wiki]

# Environment

The following build environment is required to build this plugin

* `java-1.6` and `maven-3.0.5`

# Build

To build the plugin locally:

    mvn clean verify

# Release

To release the plugin:

    mvn release:prepare release:perform -B

# Test local instance

To test in a local Jenkins instance

    mvn hpi:run

  [wiki]: http://wiki.jenkins-ci.org/display/JENKINS/Bouncy+Castle+API+Plugin
