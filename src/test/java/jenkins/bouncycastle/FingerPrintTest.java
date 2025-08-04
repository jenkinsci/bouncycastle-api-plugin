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

package jenkins.bouncycastle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import jenkins.bouncycastle.api.PEMEncodable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class FingerPrintTest {

    private static File PEM_FILE;
    private static final String PRIVATE_KEY_FP = "3c:ee:c2:12:57:5f:d0:73:79:38:d6:aa:ef:91:0a:b8:2c:5f:47:65";
    private static final String PUBLIC_KEY_FP = "e3:cc:f6:5d:0b:bb:8b:ca:32:12:fd:70:98:57:c0:21";

    @BeforeAll
    static void setUpBC() throws URISyntaxException {
        Security.addProvider(new BouncyCastleProvider());
        PEM_FILE = new File(EncodingDecodingTest.class
                .getClassLoader()
                .getResource("private-key-fingerprint.pem")
                .toURI());
    }

    @AfterAll
    static void cleanupProvider() {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    @Test
    void testPrivateFingerprint() throws Exception {
        PEMEncodable pemCodec = PEMEncodable.read(PEM_FILE);
        assertEquals(PRIVATE_KEY_FP, pemCodec.getPrivateKeyFingerprint());

        PEMEncodable pemCodecOnlyPublic = PEMEncodable.create(pemCodec.toPublicKey());
        assertEquals(PUBLIC_KEY_FP, pemCodecOnlyPublic.getPublicKeyFingerprint());
        assertNull(pemCodecOnlyPublic.getPrivateKeyFingerprint());
    }

    @Test
    void testPublicFingerprint() throws Exception {
        PEMEncodable pemCodec = PEMEncodable.read(PEM_FILE);
        assertEquals(PUBLIC_KEY_FP, pemCodec.getPublicKeyFingerprint());

        PEMEncodable pemCodecOnlyPrivate = PEMEncodable.create(pemCodec.toPrivateKey());
        assertEquals(PRIVATE_KEY_FP, pemCodecOnlyPrivate.getPrivateKeyFingerprint());
        assertNull(pemCodecOnlyPrivate.getPublicKeyFingerprint());
    }

    @Test
    void testUnsupportedCodec() throws Exception {
        PEMEncodable pemCodec = PEMEncodable.read(PEM_FILE);
        assertThrows(NoSuchAlgorithmException.class, () -> PEMEncodable.getKeyDigest(pemCodec.toPrivateKey(), "XYZ"));
    }
}
