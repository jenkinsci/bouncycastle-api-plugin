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

package jenkins.bouncycastle;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.junit.BeforeClass;
import org.junit.Test;

import jenkins.bouncycastle.api.PEMManager;

public class FingerPrintTest {

    private static File PEM_FILE;
    private static final String PRIVATE_KEY_FP = "3c:ee:c2:12:57:5f:d0:73:79:38:d6:aa:ef:91:0a:b8:2c:5f:47:65";
    private static final String PUBLIC_KEY_FP = "e3:cc:f6:5d:0b:bb:8b:ca:32:12:fd:70:98:57:c0:21";

    @BeforeClass
    public static void setUpBC() throws URISyntaxException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        PEM_FILE = new File(
                EncodignDecodingTest.class.getClassLoader().getResource("private-key-fingerprint.pem").toURI());
    }

    @Test
    public void testPrivateFingerprint() throws IOException {
        PEMManager pemCodec = new PEMManager(PEM_FILE);
        assertEquals(PRIVATE_KEY_FP, pemCodec.getPrivateKeyFingerprint());

        PEMManager pemCodecOnlyPublic = new PEMManager(pemCodec.toPublicKey());
        assertEquals(PUBLIC_KEY_FP, pemCodecOnlyPublic.getPublicKeyFingerprint());
        assertEquals(null, pemCodecOnlyPublic.getPrivateKeyFingerprint());
    }

    @Test
    public void testPublicFingerprint() throws IOException {
        PEMManager pemCodec = new PEMManager(PEM_FILE);
        assertEquals(PUBLIC_KEY_FP, pemCodec.getPublicKeyFingerprint());

        PEMManager pemCodecOnlyPrivate = new PEMManager(pemCodec.toPrivateKey());
        assertEquals(PRIVATE_KEY_FP, pemCodecOnlyPrivate.getPrivateKeyFingerprint());
        assertEquals(null, pemCodecOnlyPrivate.getPublicKeyFingerprint());
    }

    @Test(expected = NoSuchAlgorithmException.class)
    public void testUnsuportedCodec() throws IOException, NoSuchAlgorithmException {
        PEMManager pemCodec = new PEMManager(PEM_FILE);
        PEMManager.getKeyDigest(pemCodec.toPrivateKey(), "XYZ");
    }
}
