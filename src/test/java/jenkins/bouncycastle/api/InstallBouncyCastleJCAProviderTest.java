package jenkins.bouncycastle.api;

import java.security.Provider;
import java.security.Security;
import java.util.stream.IntStream;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import hudson.remoting.Channel;
import hudson.slaves.DumbSlave;
import jenkins.security.MasterToSlaveCallable;

public class InstallBouncyCastleJCAProviderTest {

    @Rule
    public JenkinsRule r = new JenkinsRule();

    private void testRegistration(boolean prioritize) throws Exception {
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
            Assert.assertTrue("Expected BC position equal to 2, but got: " + position, position == 2);
        } else {
            Assert.assertTrue("Expected BC position greater than 2, but got: " + position, position > 2);
        }
    }

    @Test
    public void testDefaultRegistration() throws Exception {
        testRegistration(false);
    }

    @Test
    public void testPriorityRegistration() throws Exception {
        testRegistration(true);
    }

    static final class GetBouncyCastleProviderPosition extends MasterToSlaveCallable<Integer, Exception> {

        private static final long serialVersionUID = 1L;

        @Override
        public Integer call() throws Exception {
            Provider[] providers = Security.getProviders();
            return IntStream.range(0, providers.length)
                    .filter(i -> "BC".equals(providers[i].getName())) // find BC by its name
                    .map(i -> i + 1) // start counting positions at 1 instead of 0
                    .findFirst()
                    .orElse(-1); // if BC not found
        }

    }

}
