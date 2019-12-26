# Release Notes (archive)

### New versions

See [GitHub Releases](https://github.com/jenkinsci/bouncycastle-api-plugin/releases) for recent versions.

### 2.17

Release date: (Aug 21, 2018)

-   [JENKINS-53074](https://issues.jenkins-ci.org/browse/JENKINS-53074) -
    Bouncy Castle library (bcpkix-jdk15on) updated to 1.60.
- Jenkins 2.60.3+ and Java 8 are now required.

### 2.16.3

Release date: (Jun 6, 2018)

-   [JENKINS-50915](https://issues.jenkins-ci.org/browse/JENKINS-50915) -
    Bouncy Castle library (bcpkix-jdk15on) updated to 1.59

### 2.16.2

Release date: (Jul 24, 2017)

-   [JENKINS-45621](https://issues.jenkins-ci.org/browse/JENKINS-45621) -
    Bouncy Castle library (bcpkix-jdk15on) updated to 1.57

### 2.16.1

Release date: (Apr 4, 2017)

-   [JENKINS-41978](https://issues.jenkins-ci.org/browse/JENKINS-41978) -
    Fixed `NullPointerException` when a PEM file couldn't be read.
-   Reduce startup log level from `INFO` to `FINE`.

### 2.16.0

Release date: (Jul 27, 2016)

**MAJOR IMPROVEMENT:** [JENKINS-36923](https://issues.jenkins-ci.org/browse/JENKINS-36923)
- Move bcpkix dependency from jenkins-war to bouncycastle-api plugin.
*Requires Jenkins 2.16 or newer*. 

### 1.648.3

Release date: (Jun 17, 2016)

*Bugfix*: [JENKINS-36035](https://issues.jenkins-ci.org/browse/JENKINS-36035) - Register
Bouncy Castle before any plugin is started

### 1.648.2

Release date: (Jun 15, 2016)

*Improvement*: [JENKINS-35696](https://issues.jenkins-ci.org/browse/JENKINS-35696) - 
Provide a mechanism to register Bouncy Castle on the build agents. 
Registration can be performed by calling `InstallBouncyCastleJCAProvider.on()`

### 1.648.1

Release date: (Jun 14, 2016)

*Bugfix*: [JENKINS-35661](https://issues.jenkins-ci.org/browse/JENKINS-35661) - When
reading PCKS8 PrivateKey it should be possible to obtain a KeyPair with `toKeyPair()`

### 1.648

Release date: (Jun 8, 2016)

Release for Jenkins versions \>= 1.648 with Bouncy Castle 1.54

### 1.0.3

Release date: (Jun 17, 2014)

*Bugfix*: [JENKINS-36035](https://issues.jenkins-ci.org/browse/JENKINS-36035) - 
Register Bouncy Castle before any plugin is started

### 1.0.2

Release date: (Jun 15, 2014)

*Improvement*: [JENKINS-35696](https://issues.jenkins-ci.org/browse/JENKINS-35696) - 
Provide a mechanism to register Bouncy Castle on the build agents. 
Registration can be performed by calling `InstallBouncyCastleJCAProvider.on()`

### 1.0.1

Release date: (Jun 14, 2016)

*Bugfix*: [JENKINS-35661](https://issues.jenkins-ci.org/browse/JENKINS-35661){.external-link} - When
reading PCKS8 PrivateKey it should be possible to obtain a KeyPair with `toKeyPair()`

### 1

Release date: (Jun 7, 2016)

First release of the API supporting Jenkins versions \>= 1.609 and \< 1.648 with BC 1.47
