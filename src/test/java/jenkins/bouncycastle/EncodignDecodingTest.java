package jenkins.bouncycastle;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.net.URISyntaxException;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Arrays;

import org.apache.commons.io.FileUtils;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import jenkins.bouncycastle.api.PEMManager;

public class EncodignDecodingTest {

    @BeforeClass
    public static void setUpBC() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private static final String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAss5HtiSf5uuHsCNwTr2vqjFgZFnAKvZ8akFNvstouA6h3oshssI4xFOWcVOAQu6u7ZNLwldwMYo1oGbvwIoSkt7L1JTgliAkXbSTdeQjbL80Tk+jGd8+gEPqcUhqCSr/GBPA/OoNkWvTR0cv1Tlna/OcLoOb+AvoYrj+wz/N8qFGOOco5eHVYEgy/YJUX//DIyS8JV9EE/3327j+VRgvDJKewc/y5iHqPMxEabexbmESuwOnEKQ7BLr0RA/8ZIIZtSFP2Eeq1rd1sXK9d3DW9i6hwiQki+NSskFfqpig2fkDVnPkPcMBTkqgV8whKp+A088yYXIowAPIs/cLU5T3bwIDAQAB";
    // "cjoc" signed with the testing keys
//    private static final String SIGNATURE = "XD8DdwOkX+o0huK8N/QS/AJyuL4mpj5lJlXlTYQZOyYoCJ892rY4Q12IDUPIT7nxBTQsqf6SIAaQda5OhBb+0RGHk5A770ANfe+OMtxBuIvhirorJ2RWjeZ+nWi6WEwSpYurBi5w73PdPJLth8MT5LmjQhKqnuFF6N/S5iyKGt108d8YAkHGDXGcRQE+AFYMaDpCqAAWhngPqe8WbbSrRwsUHXdEuAXgvlhJ0bwaK7WsConlk8fpBOQ7v9MKgfX7ww1VleDydReGzC6V2ayhXAbDs8Sp00hgc1LS/uPyumzztXqVRzkVLY3RZzASQVdM99a0WhOWdvc2W3Ycg1chKA==";
    private static File PRIVATE_KEY_PEM;
    private static File PUBLIC_KEY_PEM;

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @BeforeClass
    public static void setUpClass() throws URISyntaxException {
        PRIVATE_KEY_PEM = new File(EncodignDecodingTest.class.getClassLoader().getResource("private-key.pem").toURI());
        PUBLIC_KEY_PEM = new File(EncodignDecodingTest.class.getClassLoader().getResource("public-key.pem").toURI());
    }

    @Test
    public void testReadPrivateKeyPEM() throws Exception {
        PEMManager pemManager = new PEMManager(new File(PRIVATE_KEY_PEM.toURI()));

        assertEquals(PEMManager.encodeBase64(pemManager.getKeyPair().getPrivate().getEncoded()),
                PEMManager.encodeBase64(pemManager.getPrivateKey().getEncoded()));
        assertEquals(PUBLIC_KEY, PEMManager.encodeBase64(pemManager.getKeyPair().getPublic().getEncoded()));
        assertEquals(PUBLIC_KEY, PEMManager.encodeBase64(pemManager.getPublicKey().getEncoded()));
    }

    @Test
    public void testReadOnlyPrivateKeyPEM() throws Exception {
        File onlyPrivate = folder.newFile("from-private.prm");

        PEMManager pemManager = new PEMManager(PRIVATE_KEY_PEM);
        PEMManager pemManagerOnlyPrivate = new PEMManager(pemManager.getPrivateKey());

        pemManagerOnlyPrivate.encodePEM(onlyPrivate);
        assertEquals(true, Arrays.equals(pemManagerOnlyPrivate.getPrivateKey().getEncoded(),pemManager.getPrivateKey().getEncoded()));
        assertEquals(FileUtils.readFileToString(PRIVATE_KEY_PEM), FileUtils.readFileToString(onlyPrivate));
    }

    @Test
    public void testReadPublicKeyPEM() throws Exception {
        PEMManager pemManager = new PEMManager(PUBLIC_KEY_PEM);

        assertEquals(PUBLIC_KEY, PEMManager.encodeBase64(pemManager.getPublicKey().getEncoded()));
    }

    @Test
    public void testReadInexistentFromPublicKey() throws Exception {
        PEMManager pemManager = new PEMManager(PUBLIC_KEY_PEM);
        assertEquals(null, pemManager.getPrivateKey());
        assertEquals(null, pemManager.getKeyPair());
        assertEquals(null, pemManager.getCertificate());
    }

    @Test
    public void testReadInexistentFromPrivateKey() throws Exception {
        PEMManager pemManager = new PEMManager(PRIVATE_KEY_PEM);

        PEMManager pemManagerOnlyPrivate = new PEMManager(pemManager.getKeyPair().getPrivate());

        assertEquals(null, pemManagerOnlyPrivate.getPublicKey());
        assertEquals(null, pemManagerOnlyPrivate.getKeyPair());
        assertEquals(null, pemManagerOnlyPrivate.getCertificate());

    }

    @Test
    public void testWritePublicKeyPEM() throws Exception {
        File pemFileNew = folder.newFile("public-key-test.pem");

        PEMManager pemManager = new PEMManager(PUBLIC_KEY_PEM);
        pemManager.encodePEM(pemFileNew);

        assertEquals(FileUtils.readFileToString(PUBLIC_KEY_PEM), FileUtils.readFileToString(pemFileNew));
    }

    @Test
    public void testWritePrivateKeyPEM() throws Exception {
        File pemFileNew = folder.newFile("private-key-test.pem");

        PEMManager pemManager = new PEMManager(PRIVATE_KEY_PEM);
        pemManager.encodePEM(pemFileNew);

        assertEquals(FileUtils.readFileToString(PRIVATE_KEY_PEM), FileUtils.readFileToString(pemFileNew));
    }

    @Test
    public void testCreationFromObjectPublicKeyPEM() throws Exception {
        File pemFileNew = folder.newFile("public-key-test.pem");

        PEMManager pemManager = new PEMManager(PUBLIC_KEY_PEM);
        new PEMManager(pemManager.getPublicKey()).encodePEM(pemFileNew);

        assertEquals(FileUtils.readFileToString(PUBLIC_KEY_PEM), FileUtils.readFileToString(pemFileNew));
    }

    @Test
    public void testCreationFromObjectPrivateKeyPEM() throws Exception {
        File pemFileNew = folder.newFile("private-key-test.pem");

        PEMManager pemManager = new PEMManager(PRIVATE_KEY_PEM);
        new PEMManager(pemManager.getKeyPair()).encodePEM(pemFileNew);

        assertEquals(FileUtils.readFileToString(PRIVATE_KEY_PEM), FileUtils.readFileToString(pemFileNew));
    }

    @Test
    public void testBase64() throws Exception {
        PEMManager pemManager = new PEMManager(PRIVATE_KEY_PEM);

        PrivateKey privateKey = pemManager.getKeyPair().getPrivate();
        String encodedPrivateKey = PEMManager.encodeBase64(privateKey.getEncoded());

        assertEquals(true, Arrays.equals(pemManager.getKeyPair().getPrivate().getEncoded(),
                PEMManager.decodeBase64(encodedPrivateKey)));
    }
}