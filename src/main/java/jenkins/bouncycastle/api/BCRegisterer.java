/*
 * The MIT License
 *
 * Copyright (c) 2016, CloudBees, Inc.
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
import java.io.IOException;
import java.security.Security;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.annotation.Nonnull;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import hudson.remoting.Channel;
import hudson.remoting.Future;
import jenkins.security.MasterToSlaveCallable;

/**
 * Allows registering Bouncy Castle on a remote agent. Just call {@link #registerBCOnSlave} and check for the
 * {@link Future} result
 */
public class BCRegisterer extends MasterToSlaveCallable<Boolean, Exception> {

    /**
     * Ensure standardized serialization.
     */
    private static final long serialVersionUID = 1L;

    /**
     * The property that holds the future for registration.
     */
    private static final ChannelProperty<Future> BOUNCYCASTLE_REGISTERED
            = new ChannelProperty<Future>(Future.class, "Bouncy Castle Registered");

    /**
     * Constructor.
     */
    private BCRegisterer() {
    }

    /**
     * {@inheritDoc}
     */
    @Nonnull
    public Boolean call() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        return Boolean.TRUE;
    }

    /**
     * Registers bouncy castle on the slave JVM
     * 
     * @param channel to the slave
     * @return Future with the result of the operation
     * @throws Exception if there is a problem registering bouncycastle
     */
    @Nonnull
    public static void registerBCOnSlave(@Nonnull Channel channel) throws IOException, InterruptedException {
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
                    future = channel.callAsync(new BCRegisterer());
                    channel.setProperty(BOUNCYCASTLE_REGISTERED, future);
                }
                future.get(1, TimeUnit.MINUTES);
            }
        } catch (IOException e) {
            throw e;
        } catch (TimeoutException e) {
            throw new IOException("Remote operation timed out", e);
        } catch (InterruptedException e) {
            throw e;
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
