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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.contentOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.util.encoders.Base64;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.jvnet.hudson.test.Issue;

import jenkins.bouncycastle.api.PEMEncodable;

public class EncodingDecodingTest {

    @BeforeClass
    public static void setUpBC() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private static final String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAss5HtiSf5uuHsCNwTr2vqjFgZFnAKvZ8akFNvstouA6h3oshssI4xFOWcVOAQu6u7ZNLwldwMYo1oGbvwIoSkt7L1JTgliAkXbSTdeQjbL80Tk+jGd8+gEPqcUhqCSr/GBPA/OoNkWvTR0cv1Tlna/OcLoOb+AvoYrj+wz/N8qFGOOco5eHVYEgy/YJUX//DIyS8JV9EE/3327j+VRgvDJKewc/y5iHqPMxEabexbmESuwOnEKQ7BLr0RA/8ZIIZtSFP2Eeq1rd1sXK9d3DW9i6hwiQki+NSskFfqpig2fkDVnPkPcMBTkqgV8whKp+A088yYXIowAPIs/cLU5T3bwIDAQAB";
    // private static final String SIGNATURE =
    // "XD8DdwOkX+o0huK8N/QS/AJyuL4mpj5lJlXlTYQZOyYoCJ892rY4Q12IDUPIT7nxBTQsqf6SIAaQda5OhBb+0RGHk5A770ANfe+OMtxBuIvhirorJ2RWjeZ+nWi6WEwSpYurBi5w73PdPJLth8MT5LmjQhKqnuFF6N/S5iyKGt108d8YAkHGDXGcRQE+AFYMaDpCqAAWhngPqe8WbbSrRwsUHXdEuAXgvlhJ0bwaK7WsConlk8fpBOQ7v9MKgfX7ww1VleDydReGzC6V2ayhXAbDs8Sp00hgc1LS/uPyumzztXqVRzkVLY3RZzASQVdM99a0WhOWdvc2W3Ycg1chKA==";
    private static File PRIVATE_KEY_PEM;
    private static File PRIVATE_KEY_PW_PEM;
    private static File PUBLIC_KEY_PEM;
    private static File CERTIFICATE_PEM;
    private static File CERTIFICATE_PUBLIC_KEY_PEM;
    private static File CERTIFICATE_PW_PEM;
    private static File CERTIFICATE_PUBLIC_KEY_PW_PEM;

    private static final String PRIVATE_KEY_PW = "test";

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @BeforeClass
    public static void setUpClass() throws URISyntaxException {
        PRIVATE_KEY_PEM = getResourceFile("private-key.pem");
        PRIVATE_KEY_PW_PEM = getResourceFile("private-key-with-password.pem");
        PUBLIC_KEY_PEM = getResourceFile("public-key.pem");
        CERTIFICATE_PEM = getResourceFile("test_cert_cert.pem");
        CERTIFICATE_PUBLIC_KEY_PEM = getResourceFile("test_cert_key.pem");
        CERTIFICATE_PW_PEM = getResourceFile("test_cert_cert_pass.pem");
        CERTIFICATE_PUBLIC_KEY_PW_PEM = getResourceFile("test_cert_key_pass.pem");
    }

    private static File getResourceFile(String resource) throws URISyntaxException {
        return new File(EncodingDecodingTest.class.getClassLoader().getResource(resource).toURI());
    }

    @Test
    public void testReadPrivateKeyPEM() throws Exception {
        PEMEncodable pemEnc = PEMEncodable.read(PRIVATE_KEY_PEM);

        assertEquals(
                new String(Base64.encode(pemEnc.toKeyPair().getPrivate().getEncoded()), StandardCharsets.UTF_8),
                new String(Base64.encode(pemEnc.toPrivateKey().getEncoded()), StandardCharsets.UTF_8));
        assertEquals(PUBLIC_KEY,
                new String(Base64.encode(pemEnc.toKeyPair().getPublic().getEncoded()), StandardCharsets.UTF_8));
        assertEquals(PUBLIC_KEY,
                new String(Base64.encode(pemEnc.toPublicKey().getEncoded()), StandardCharsets.UTF_8));
    }

    @Test
    public void testReadPrivateKeyWithPasswordPEM() throws Exception {
        PEMEncodable pemEnc = PEMEncodable.read(PRIVATE_KEY_PW_PEM, PRIVATE_KEY_PW.toCharArray());

        assertEquals(
                new String(Base64.encode(pemEnc.toKeyPair().getPrivate().getEncoded()), StandardCharsets.UTF_8),
                new String(Base64.encode(pemEnc.toPrivateKey().getEncoded()), StandardCharsets.UTF_8));
        assertEquals(PUBLIC_KEY,
                new String(Base64.encode(pemEnc.toKeyPair().getPublic().getEncoded()), StandardCharsets.UTF_8));
        assertEquals(PUBLIC_KEY,
                new String(Base64.encode(pemEnc.toPublicKey().getEncoded()), StandardCharsets.UTF_8));
    }

    @Test
    public void testReadOnlyPrivateKeyPEM() throws Exception {
        File onlyPrivate = folder.newFile("from-private.prm");

        PEMEncodable pemEnc = PEMEncodable.read(PRIVATE_KEY_PEM);
        PEMEncodable pemEncOnlyPrivate = PEMEncodable.create(pemEnc.toPrivateKey());

        pemEncOnlyPrivate.write(onlyPrivate);
        assertTrue(Arrays.equals(pemEncOnlyPrivate.toPrivateKey().getEncoded(),
                pemEnc.toPrivateKey().getEncoded()));
        assertThat(contentOf(onlyPrivate)).isEqualToNormalizingNewlines(contentOf(PRIVATE_KEY_PEM));
    }

    @Test
    public void testReadPublicKeyPEM() throws Exception {
        PEMEncodable pemEnc = PEMEncodable.read(PUBLIC_KEY_PEM);

        assertEquals(PUBLIC_KEY,
                new String(Base64.encode(pemEnc.toPublicKey().getEncoded()), StandardCharsets.UTF_8));
    }

    @Test
    public void testReadInexistentFromPublicKey() throws Exception {
        PEMEncodable pemEnc = PEMEncodable.read(PUBLIC_KEY_PEM);
        assertNull(pemEnc.toPrivateKey());
        assertNull(pemEnc.toKeyPair());
        assertNull(pemEnc.toCertificate());
    }

    @Test
    public void testReadInexistentFromPrivateKey() throws Exception {
        PEMEncodable pemEnc = PEMEncodable.read(PRIVATE_KEY_PEM);

        PEMEncodable pemEncOnlyPrivate = PEMEncodable.create(pemEnc.toKeyPair().getPrivate());

        assertNull(pemEncOnlyPrivate.toPublicKey());
        assertNull(pemEncOnlyPrivate.toKeyPair());
        assertNull(pemEncOnlyPrivate.toCertificate());

    }

    @Test
    public void testReadCertificatePEM() throws Exception {
        PEMEncodable pemEncCer = PEMEncodable.read(CERTIFICATE_PEM);
        PEMEncodable pemEncKey = PEMEncodable.read(CERTIFICATE_PUBLIC_KEY_PEM);

        Certificate certificate = pemEncCer.toCertificate();
        PublicKey publicKey = pemEncKey.toPublicKey();
        assertNotNull(certificate);
        assertNotNull(publicKey);
        assertEquals(new String(Base64.encode(certificate.getPublicKey().getEncoded()), StandardCharsets.UTF_8),
                new String(Base64.encode(publicKey.getEncoded()), StandardCharsets.UTF_8));
    }

    @Test
    public void testReadCertificateWithPasswordPEM() throws Exception {
        PEMEncodable pemEncCer = PEMEncodable.read(CERTIFICATE_PW_PEM);
        PEMEncodable pemEncKey = PEMEncodable.read(CERTIFICATE_PUBLIC_KEY_PW_PEM);

        Certificate certificate = pemEncCer.toCertificate();
        PublicKey publicKey = pemEncKey.toPublicKey();
        assertNotNull(certificate);
        assertNotNull(publicKey);
        assertEquals(new String(Base64.encode(certificate.getPublicKey().getEncoded()), StandardCharsets.UTF_8),
                new String(Base64.encode(publicKey.getEncoded()), StandardCharsets.UTF_8));
    }

    @Test
    public void testWritePublicKeyPEM() throws Exception {
        File pemFileNew = folder.newFile("public-key-test.pem");

        PEMEncodable pemEnc = PEMEncodable.read(PUBLIC_KEY_PEM);
        pemEnc.write(pemFileNew);

        assertThat(contentOf(pemFileNew)).isEqualToNormalizingNewlines(contentOf(PUBLIC_KEY_PEM));
    }

    @Test
    public void testWritePrivateKeyPEM() throws Exception {
        File pemFileNew = folder.newFile("private-key-test.pem");

        PEMEncodable pemEnc = PEMEncodable.read(PRIVATE_KEY_PEM);
        pemEnc.write(pemFileNew);

        assertThat(contentOf(pemFileNew)).isEqualToNormalizingNewlines(contentOf(PRIVATE_KEY_PEM));
    }

    @Test
    public void testWriteCertificatePEM() throws Exception {
        File pemFileNew = folder.newFile("certificate-test.pem");

        PEMEncodable pemEnc = PEMEncodable.read(CERTIFICATE_PW_PEM);
        pemEnc.write(pemFileNew);

        assertThat(contentOf(pemFileNew)).isEqualToNormalizingNewlines(contentOf(CERTIFICATE_PW_PEM));
    }

    @Test
    public void testCreationFromObjectPublicKeyPEM() throws Exception {
        File pemFileNew = folder.newFile("public-key-test.pem");

        PEMEncodable pemEnc = PEMEncodable.read(PUBLIC_KEY_PEM);
        PEMEncodable.create(pemEnc.toPublicKey()).write(pemFileNew);

        assertThat(contentOf(pemFileNew)).isEqualToNormalizingNewlines(contentOf(PUBLIC_KEY_PEM));
    }

    @Test
    public void testCreationFromObjectPrivateKeyPEM() throws Exception {
        File pemFileNew = folder.newFile("private-key-test.pem");

        PEMEncodable pemEnc = PEMEncodable.read(PRIVATE_KEY_PEM);
        PEMEncodable.create(pemEnc.toKeyPair()).write(pemFileNew);

        assertThat(contentOf(pemFileNew)).isEqualToNormalizingNewlines(contentOf(PRIVATE_KEY_PEM));
    }
    
    
    @Test
    @Issue(value="JENKINS-35661") 
    public void testReadKeyPairFromPCKS8PEM() throws Exception {
        PEMEncodable pemEnc = PEMEncodable.read(getResourceFile("private-key-pcks8.pem"));
        assertNotNull(pemEnc.toKeyPair());
        assertNotNull(pemEnc.toPrivateKey());
        assertNotNull(pemEnc.toPublicKey());
    }

    @Test(expected = IOException.class)
    @Issue(value = "JENKINS-41978")
    public void testInvalidPEM() throws Exception {
        PEMEncodable.decode(FileUtils.readFileToString(getResourceFile("invalid.pem")));
    }
}
