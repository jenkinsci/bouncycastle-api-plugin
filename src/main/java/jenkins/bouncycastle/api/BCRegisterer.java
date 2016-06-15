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

import java.security.Security;

import javax.annotation.Nonnull;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import hudson.remoting.Channel;
import hudson.remoting.Future;
import jenkins.security.MasterToSlaveCallable;

/**
 * Allows registering Bouncy Castle on a remote agent. Just call {@link registerBCOnSlave} and check for the
 * {@link Future} result
 */
public class BCRegisterer extends MasterToSlaveCallable<Boolean, Exception> {

    private static final long serialVersionUID = 1L;

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

    private static final String BOUNCYCASTLE_REGISTERED = "bouncycastle.registered";

    /**
     * Registers bouncy castle on the slave JVM
     * 
     * @param channel to the slave
     * @return Future with the result of the operation
     * @throws Exception if there is a problem registering bouncycastle
     */
    @Nonnull
    public static Future<Boolean> registerBCOnSlave(@Nonnull Channel channel) throws Exception {
        Object property = channel.getProperty(BOUNCYCASTLE_REGISTERED);
        Future<Boolean> future = property instanceof Future ? (Future<Boolean>) property : null;

        if (future != null) {
            return future;
        } else {
            // pre-loading the bouncyclastle jar to make sure the JVM reconizes the signature
            channel.preloadJar(PEMEncodable.class.getClassLoader(), BouncyCastleProvider.class);
            future = channel.callAsync(new BCRegisterer());
            channel.setProperty(BOUNCYCASTLE_REGISTERED, future);
            return future;
        }
    }
}