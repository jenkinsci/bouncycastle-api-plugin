package jenkins.bouncycastle.api;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Utility class for registration of the BouncyCastle security provider.
 */
@Restricted(NoExternalUse.class)
class BcProviderRegistration {

    /**
     * If true, BC will be inserted at the beginning of the security providers list (in 2nd position).
     * Otherwise, it will be added at the end of the list (default behaviour).
     * This property, when set on the main Jenkins process, also affects BC registration on agent
     * processes via {@link InstallBouncyCastleJCAProvider}.
     */
    static boolean PRIORITIZE = Boolean.getBoolean("jenkins.bouncycastle.prioritizeJceProvider");

    /**
     * Register the BC provider, either at the beginning (2nd position) or end of the providers list,
     * depending on the {@link #PRIORITIZE} value.
     */
    static void register() {
        register(PRIORITIZE);
    }

    /**
     * Register the BC provider, either at the beginning (2nd position) or end of the providers list.
     *
     * @param prioritize if {@code true}, the provider is registered at the beginning of the providers list
     */
    static void register(boolean prioritize) {
        if (prioritize) {
            // insert at 2nd position, following recommendation to not change the first provider:
            // http://www.bouncycastle.org/wiki/display/JA1/Provider+Installation
            Security.insertProviderAt(new BouncyCastleProvider(), 2);
        } else {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

}