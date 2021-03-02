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

import java.security.Security;
import java.util.logging.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import hudson.Plugin;

/**
 * Initialization class to register Bouncy Castle as a security provider.
 * 
 * @since 1.0
 */
public class SecurityProviderInitializer extends Plugin {
   
    private static final Logger LOGGER = Logger.getLogger(SecurityProviderInitializer.class.getName());
    
    static{
        /*
         * FIXME: We should do it with the @Initializer but some other plugins are loading before this one 
         * and failing because of BC not being registered. It seems to be a core related bug that is not 
         * resolving the dependency graph correctly.
         */

        addSecurityProvider();
    }
    
    /**
     * Initializes JVM security to Bouncy Castle. This initialization should be done before any plugin is loaded in
     * order to ensure that the provider is available to any plugin that needs it and that we are the first to register
     * it.
     * 
     */
    //@Initializer(before = InitMilestone.STARTED)
    @Restricted(NoExternalUse.class)
    public static void addSecurityProvider() {
        LOGGER.fine("Initializing Bouncy Castle security provider.");
        Security.addProvider(new BouncyCastleProvider());
        LOGGER.fine("Bouncy Castle security provider initialized.");
    }

}