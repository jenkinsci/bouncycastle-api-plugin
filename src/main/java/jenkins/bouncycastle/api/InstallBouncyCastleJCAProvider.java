/*
 * The MIT License
 *
 * Copyright (c) 2016-2021, CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package jenkins.bouncycastle.api;

import hudson.remoting.ChannelProperty;
import hudson.slaves.SlaveComputer;
import java.io.IOException;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Logger;
import javax.annotation.Nonnull;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import hudson.remoting.Channel;
import hudson.remoting.Future;
import jenkins.security.MasterToSlaveCallable;

/**
 * Allows registering Bouncy Castle on a remote agent. Just call {@link #on(Channel)} or {@link #on(SlaveComputer)}.
 *
 * @since 1.648.2
 */
public class InstallBouncyCastleJCAProvider extends MasterToSlaveCallable<Boolean, Exception> {

    private static Logger LOG = Logger.getLogger(InstallBouncyCastleJCAProvider.class.getName());
    /**
     * Ensure standardized serialization.
     */
    private static final long serialVersionUID = 1L;

    /**
     * The property that holds the future for registration.
     */
    private static final ChannelProperty<Future> BOUNCYCASTLE_REGISTERED
            = new ChannelProperty<>(Future.class, "Bouncy Castle Registered");

    private final boolean prioritize;

    /**
     * Constructor.
     *
     * @param prioritize whether BC should be prioritized (inserted at 2nd position) in the
     * JCE providers list, or simply added last.
     */
    private InstallBouncyCastleJCAProvider(boolean prioritize) {
        this.prioritize = prioritize;
    }

    /**
     * {@inheritDoc}
     */
    @Nonnull
    public Boolean call() throws Exception {
        BcProviderRegistration.register(prioritize);
        return Boolean.TRUE;
    }

    /**
     * Registers bouncy castle on the slave JVM
     * 
     * @param c the slave
     * @throws IOException if there is a problem registering bouncycastle
     * @throws InterruptedException if interrupted while trying to register
     * @throws SecurityException if the remote JVM has a security manager
     * @throws LinkageError if there was a classloading issue on the remote agent.
     */
    public static void on(@Nonnull SlaveComputer c) throws IOException, InterruptedException {
        Channel channel = c.getChannel();
        if (channel != null) {
            on(channel);
        } else {
            throw new IOException("Remote agent is off-line");
        }
    }
     /**
     * Registers bouncy castle on the slave JVM
     *
     * @param channel the {@link Channel}
     * @throws IOException if there is a problem registering bouncycastle
     * @throws InterruptedException if interrupted while trying to register
     * @throws SecurityException if the remote JVM has a security manager
     * @throws LinkageError if there was a classloading issue on the remote agent.
     */
    public static void on(@Nonnull Channel channel) throws IOException, InterruptedException {
        if (!BouncyCastlePlugin.isActive()) {
            return;
        }
        Future future = channel.getProperty(BOUNCYCASTLE_REGISTERED);

        try {
            if (future != null) {
                future.get(1, TimeUnit.MINUTES);
            } else {
                // pre-loading the bouncyclastle jar to make sure the JVM recognizes the signature
                channel.preloadJar(PEMEncodable.class.getClassLoader(), BouncyCastleProvider.class);
                // check again just in case we have a parallel pre-loader
                future = channel.getProperty(BOUNCYCASTLE_REGISTERED);
                if (future == null) {
                    // if we end up here in parallel it will be an idempotent operation, so no harm anyway
                    future = channel.callAsync(new InstallBouncyCastleJCAProvider(BcProviderRegistration.PRIORITIZE));
                    channel.setProperty(BOUNCYCASTLE_REGISTERED, future);
                }
                future.get(1, TimeUnit.MINUTES);
            }
        } catch (TimeoutException e) {
            throw new IOException("Remote operation timed out", e);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof IOException) {
                throw new IOException(e);
            }
            if (e.getCause() instanceof SecurityException) {
                throw new SecurityException(e);
            }
            if (e.getCause() instanceof LinkageError) {
                throw new LinkageError("Could not register bouncy castle", e);
            }
            throw new IOException("Could not register bouncy castle", e);
        }
    }
}
