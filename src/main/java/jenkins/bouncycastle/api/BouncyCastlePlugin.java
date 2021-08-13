package jenkins.bouncycastle.api;

import java.io.File;
import java.security.Provider;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.accmod.restrictions.suppressions.SuppressRestrictedWarnings;
import hudson.Main;
import hudson.Plugin;
import hudson.PluginWrapper;
import jenkins.model.Jenkins;
import jenkins.util.AntClassLoader;

@SuppressWarnings("deprecation") // there is no other way to achieve this at the correct lifecycle point
@Restricted(NoExternalUse.class) // just for Jenkins access not part of the API
public class BouncyCastlePlugin extends Plugin {

    private static final Logger LOG = Logger.getLogger(BouncyCastlePlugin.class.getName());

    private static final boolean isActive;

    static {
        // BouncyCastle FIPS is installed in the JVM, we can not install over the top of it so do not try
        Provider p = Security.getProvider("BCFIPS");
        isActive = (p == null);

        LOG.log(Level.CONFIG,
                isActive ? "BouncyCastle Providers from BouncyCastle API plugin will be active" :
                           "Detected the presence of the BouncyCastle FIPS provider, the regular BouncyCastle JARs will not be available.");
    }

    @Override
    @SuppressRestrictedWarnings(jenkins.util.AntClassLoader.class) // we are messing with the classloader and it has not changed in many many years
    public void start() throws Exception {
        if (!isActive) {
            // Alternative BouncyCastle is installed do no not insert these libraries
            return;
        }
        // this is the hairy part.
        // add the BouncyCastle APIs into the classpath for other plugins (and this plugin to use!)
        /*
         * Whilst plugins that have code may go boom before this with class loading issues, extensions (at this point)
         * have not been discovered, so this would only affect people using the deprecated `Plugin` class (like we are!)
         */

        final File optionalLibDir = getOptionalLibDirectory();
        File[] optionalLibs = optionalLibDir.listFiles();

        if (optionalLibs == null || optionalLibs.length == 0) {
            if (Main.isUnitTest) {
                LOG.log(Level.INFO, "No optional-libs found, for non RealJenkinsRule this is fine and can be ignored.");
            } else {
                LOG.log(Level.WARNING, "No optional-libs not found at {0}, BouncyCastle APIs will be unavailable causing strange runtime issues.", optionalLibDir);
                // fail fast, most likely a packaging issue
                throw new IllegalStateException("BouncyCastle libs are missing from WEB-INF/optional-libs");
            }
        } else {
            AntClassLoader cl = (AntClassLoader) this.getWrapper().classLoader;

            for (File optionalLib : optionalLibs) {
                LOG.log(Level.CONFIG, () -> "Inserting " + optionalLib + " into bouncycastle-api plugin classpath");
                cl.addPathComponent(optionalLib);
            }
        }
        SecurityProviderInitializer.addSecurityProvider();
    }

    public static boolean isActive() {
        return isActive;
    }


    private final File getOptionalLibDirectory() {
        PluginWrapper pw = getWrapper();
        File explodedPluginsDir = pw.parent.getWorkDir();
        if (explodedPluginsDir == null) {
            // not overridden use default of ${JENKINS_HOME}/plugins
            explodedPluginsDir = new File(Jenkins.get().getRootDir(), "plugins");
            LOG.log(Level.FINE, "plugindir not specified, falling back to $'{'JENKINS_HOME/plugins'}' as {0}", explodedPluginsDir);
        }
        File f =  new File(explodedPluginsDir, pw.getShortName() + "/WEB-INF/optional-lib/");
        LOG.log(Level.FINE, "using {0} as the optional-lib directory", f);
        return f;
    }
}
