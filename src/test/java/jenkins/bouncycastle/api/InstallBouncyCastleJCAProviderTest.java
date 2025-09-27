package jenkins.bouncycastle.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.remoting.Channel;
import hudson.slaves.DumbSlave;
import java.io.Serial;
import java.security.Provider;
import java.security.Security;
import java.util.stream.IntStream;
import jenkins.security.MasterToSlaveCallable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class InstallBouncyCastleJCAProviderTest {

    @BeforeAll
    static void validateEnv() {
        assertNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME));
    }

    @AfterAll
    static void cleanupProvider() {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    private static void testRegistration(JenkinsRule r, boolean prioritize) throws Exception {
        DumbSlave s = r.createOnlineSlave();
        Channel c = s.getComputer().getChannel();

        boolean backup = BcProviderRegistration.PRIORITIZE;
        BcProviderRegistration.PRIORITIZE = prioritize;
        try {
            InstallBouncyCastleJCAProvider.on(c);
        } finally {
            BcProviderRegistration.PRIORITIZE = backup;
        }

        int position = c.call(new GetBouncyCastleProviderPosition());
        if (prioritize) {
            assertEquals(2, position, "Expected BC position equal to 2, but got: " + position);
        } else {
            assertTrue(position > 2, "Expected BC position greater than 2, but got: " + position);
        }
    }

    @Test
    void testDefaultRegistration(JenkinsRule r) throws Exception {
        testRegistration(r, false);
    }

    @Test
    void testPriorityRegistration(JenkinsRule r) throws Exception {
        testRegistration(r, true);
    }

    static final class GetBouncyCastleProviderPosition extends MasterToSlaveCallable<Integer, Exception> {

        @Serial
        private static final long serialVersionUID = 1L;

        @Override
        public Integer call() {
            Provider[] providers = Security.getProviders();
            return IntStream.range(0, providers.length)
                    .filter(i -> "BC".equals(providers[i].getName())) // find BC by its name
                    .map(i -> i + 1) // start counting positions at 1 instead of 0
                    .findFirst()
                    .orElse(-1); // if BC not found
        }
    }
}
