package jenkins.bouncycastle.api;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.Provider;
import java.security.Security;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.accmod.restrictions.suppressions.SuppressRestrictedWarnings;
import hudson.Plugin;
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

        LOG.log(Level.INFO,
                isActive ? "BouncyCastle Providers from BouncyCastle API plugin will be active" :
                           "Detected the precence of the BouncyCastle FIPS provider, the regular BouncyCastle jars will not be avaialble.");
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
        final List<String> bcJars = getResourceFiles();
        AntClassLoader cl = (AntClassLoader) this.getWrapper().classLoader;

        // grab the needed resources
        for (String jar : bcJars) {
            File jarFile = locateJar(jar);
            LOG.log(Level.INFO, () -> "Inserting " + jar + " into bouncycastle-api plugin classpath");
            cl.addPathComponent(jarFile);
        }
        SecurityProviderInitializer.addSecurityProvider();
    }

    public static boolean isActive() {
        return isActive;
    }

    private static File locateJar(String name) throws IOException {
        LOG.log(Level.FINE, "Attempting to locate BouncyCastle Jar {0}", name);
        URL resourceURL = BouncyCastlePlugin.class.getResource("/bc_jars/" + name);
        if (resourceURL == null) {
            throw new IOException("Could not locate " + name + " in plugin resources");
        }
        try {
            File f = new File(resourceURL.toURI());
            LOG.log(Level.FINE, () -> "Located " + name + "  at " + f.getAbsolutePath());
            return f;
        } catch (URISyntaxException ex) {
            throw new IOException("Could not locate file for " + name + " with URI " + resourceURL, ex);
        }
    }

    private static List<String> getResourceFiles() throws IOException {
        LOG.log(Level.FINE, "Searching for BouncyCastle Jars...");

        try (InputStream in = BouncyCastlePlugin.class.getResourceAsStream("/bc_jars");
                InputStreamReader isr = new InputStreamReader(in, Charset.defaultCharset());
                BufferedReader br = new BufferedReader(isr)) {
            List<String> filenames = br.lines().collect(Collectors.toList());
            LOG.log(Level.FINE, () -> "Found the following BouncyCastle Jars: " + filenames.toString());
            return filenames;
        }
    }
}
