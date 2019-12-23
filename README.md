# Jenkins Bouncy Castle API Plugin

[JENKINS-35291](https://issues.jenkins-ci.org/browse/JENKINS-35291)

Dependency to multiple Bouncy Castle versions from jenkins core and plugins is causing problems due to the binary incompatibility between versions, the different supported algorithms, etc.

On Jenkins core 1.648, Bouncy Castle was bumped from version `1.47` to `1.54` as a result of a change in ``instance-identity`` module
* ``instance-identity-module`` bumped Bouncy Castle from `1.47` to `1.54`: [pom.xml (v 1.4)](https://github.com/jenkinsci/instance-identity-module/blob/instance-identity-1.4/pom.xml#L32) -> [pom.xml (v 1.5.1)](https://github.com/jenkinsci/instance-identity-module/blob/instance-identity-1.5.1/pom.xml#L33)
* Jenkins core bumped instance-identity-plugin:  [pom.xml (v 1.647) ](https://github.com/jenkinsci/jenkins/blob/stable-1.647/war/pom.xml#L107)-> [pom.xml (v 1.648)](https://github.com/jenkinsci/jenkins/blob/jenkins-1.648/war/pom.xml#L100)

**Problems found:**
* Plugins running in Jenkins < `1.648` get `1.47` from the parent class loader (in the default class loading strategy). If they include a later version in their own classpath, only "new" classes are seen from their referenced JAR.
* Plugins running in Jenkins >= `1.648` get `1.54` from the parent class loader (in the default class loading strategy). If they include an earlier version in their own classpath, only "removed" classes are seen from their referenced JAR.
* If the plugin is using JCA instead of BC classes directly usually the plugin works, but if ran in an BC `1.47` Jenkins core, there will be missing algorithms.
* Plugins are introducing different versions of BC which adds to de mix, potentially producing unpredictable results

**Some considerations:**
* Many plugins are only introducing BC dependency to do PEM encoding/decoding. This API got changed by the BC bump.
* instance-identity-module is using BC only for PEM encoding/decoding, removing this dependency from the core is possible

**Proposed solution**
A possible solution to this problem would to create a plugin (this plugin) from which plugins using BC will depend. Responsible for:
* Load BC into uber class loader.
* Register BC as a JVM security provider in order to allow other plugins to use JCA API with BC algorithms. 
* Provide an API to do common tasks like PEM Encoding/Decoding ensuring its stability among BC versions.

The implementation of this plugin does not expose any classes from BC, only JCA, allowing plugins to not depend on the specifics of BC.

Later some other actions would have to be taken in order to fully solve this situation, like having one version of the plugin for each version of BC, etc.

This plugin provides an stable API to Bouncy Castle related tasks. Plugins using Bouncy Castle should depend on this plugin and not directly on Bouncy Castle. See also this [plugin's wiki page][wiki]

[wiki]: http://wiki.jenkins-ci.org/display/JENKINS/Bouncy+Castle+API+Plugin
