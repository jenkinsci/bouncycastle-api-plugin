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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.util.encoders.Base64;

/**
 * A class that provides an API to manager PEM format, providing additional methods to handle Keys, Certificates,
 * Fingerprints, etc The supported algorithms will depend on the underlying version of BouncyCastle
 *
 */
public class PEMManager {

    /**
     * Stores the internal Bouncy Castle or JCA object
     */
    Object pemObject;

    /**
     * Creates a {@link PEMManager} by reading a PEM file
     * 
     * @param pemFile {@link File} pointing to the PEM file to read
     * @throws IOException launched if a problem exists reading the PEM information or the {@link File}
     */
    public PEMManager(@Nonnull File pemFile) throws IOException {
        decodePEM(pemFile);
    }

    /**
     * Creates a {@link PEMManager} by reading PEM formated data from a {@link String}
     * 
     * @param pem {@link String} with the PEM data
     * @throws IOException launched if a problem exists reading the PEM information
     */
    public PEMManager(@Nonnull String pem) throws IOException {
        decodePEM(pem);

        // TODO: Decide what to do with Password protected PEMs

        // try {
        // decodePEM(pem, new PasswordFinder() {
        // public char[] getPassword() {
        // throw new BCPrivateKeyWithPassword();
        // }
        // });
        // } catch (BCPrivateKeyWithPassword e) {
        // throw new BCException(
        // "This private key is password protected, which isn't supported yet");
        // }

    }

    /**
     *
     * Creates a {@link PEMManager} from an {@link Object} that can be of any supported type by Bouncy Castle or JCA:
     * {@link Key}, {@link PrivateKey}, {@link KeyPair}, {@link Certificate}, etc.
     *
     * @param pemObject object to manage
     */
    public PEMManager(@Nonnull Object pemObject) {
        this.pemObject = pemObject;
    }

    protected void decodePEM(@Nonnull File pemFile) throws IOException {
        decodePEM(FileUtils.readFileToString(pemFile));
    }

    protected void decodePEM(@Nonnull String pem) throws IOException {
        decodePEM(pem, null);
    }

    protected void decodePEM(@Nonnull String pem, @Nullable PasswordFinder pwf) throws IOException {
        PEMReader parser = new PEMReader(new StringReader(pem), pwf);
        try {
            pemObject = parser.readObject();
        } finally {
            parser.close();
        }
    }

    /**
     * Encodes the current stored information in PEM format and returns it as a {@link String}
     * 
     * @return PEM encoded data
     * @throws IOException launched if a problem exists generating the PEM information
     */
    @Nonnull
    public String encodePEM() throws IOException {
        StringWriter sw = new StringWriter();
        PEMWriter w = new PEMWriter(sw);
        try {
            w.writeObject(pemObject);
        } finally {
            w.close();
        }
        return sw.toString();
    }

    /**
     * Encodes the current stored information in PEM formated {@link File}
     * 
     * @throws IOException launched if a problem exists generating the PEM information or writing the {@link File}
     */
    public void encodePEM(@Nonnull File pemFile) throws IOException {
        FileUtils.writeStringToFile(pemFile, encodePEM());
    }

    /**
     * Obtain {@link KeyPair} object with the public and private key from the read PEM. No conversion is performed, the
     * read PEM must contain private and public key in order to obtain a {@link KeyPair} object, {@link null} will be
     * returned in all the other cases.
     * 
     * @return {@link KeyPair} object with public and private keys or {@link null} if the read PEM didn't contain
     * private and public keys.
     */
    @Nullable
    public KeyPair getKeyPair() {
        if (pemObject instanceof KeyPair) {
            return (KeyPair) pemObject;
        } // We will need conversion here on BC 1.54
        return null;
    }

    /**
     * Obtain {@link PublicKey} object from the read PEM. If the PEM data contained other object type like
     * {@link KeyPair} or {@link Certificate}, the public key will be extracted from them.
     * 
     * @return {@link PublicKey} with the public key, null if a public key could not be obtained from the current data
     */
    @Nullable
    public PublicKey getPublicKey() {
        if (pemObject instanceof PublicKey) {
            return (PublicKey) pemObject;
        } else if (pemObject instanceof KeyPair) {
            return ((KeyPair) pemObject).getPublic();
        } else if (pemObject instanceof Certificate) {
            return ((Certificate) pemObject).getPublicKey();
        }
        return null;
    }

    /**
     * Obtain {@link Certificate} object from the read PEM.
     * 
     * @return {@link Certificate} with the certificate, null if a certificate could not be obtained from the current
     * data
     */
    @Nullable
    public Certificate getCertificate() {
        if (pemObject instanceof Certificate) {
            return ((Certificate) pemObject);
        }
        return null;
    }

    /**
     * Obtain {@link PrivateKey} object from the read PEM. If the PEM data contained other object type like
     * {@link KeyPair}, the private key will be extracted from them.
     * 
     * @return {@link PrivateKey} with the private key, null if a private key could not be obtained from the current
     * data
     */
    @Nullable
    public PrivateKey getPrivateKey() {
        if (pemObject instanceof PrivateKey) {
            return (PrivateKey) pemObject;
        } else if (pemObject instanceof KeyPair) {
            return ((KeyPair) pemObject).getPrivate();
        }
        return null;
    }

    /**
     * Obtains the fingerprint of the private key in the "ab:cd:ef:...:12" format, which basically is an SHA1 digest
     * from the key, encoded in hex format.
     * 
     * @return private key fingerprint in hex format "ab:cd:ef:...:12", null if the private key could not be obtained
     * from the current PEM data.
     * @throws IOException thrown if a problem exists creating the fingerprint
     */
    @Nullable
    public String getPrivateKeyFingerprint() throws IOException {
        PrivateKey key = getPrivateKey();
        if (key == null) {
            return null;
        }
        return hexEncode(getKeyDigestSHA1(key));
    }

    /**
     * Obtains the fingerprint of the public key in the "ab:cd:ef:...:12" format, which basically is an MD5 digest from
     * the key, encoded in hex format.
     * 
     * @return public key fingerprint in hex format "ab:cd:ef:...:12", null if the public key could not be obtained from
     * the current PEM data.
     * @throws IOException if a problem exists creating the fingerprint
     */
    @Nullable
    public String getPublicKeyFingerprint() throws IOException {
        PublicKey key = getPublicKey();
        if (key == null) {
            return null;
        }
        return hexEncode(getKeyDigestMD5(key));
    }

    /**
     * Generates an SHA1 digest from a Key object
     * 
     * @param k the key to generate the digest from
     * @return the generated digest
     * @throws IOException if a problem exists creating the digest
     */
    @Nonnull
    public static byte[] getKeyDigestSHA1(@Nonnull Key k) throws IOException {
        return getKeyDigest(k, "SHA1");
    }

    /**
     * Generates an MD5 digest from a Key object
     * 
     * @param k the key to generate the digest from
     * @return the generated digest
     * @throws IOException if a problem exists creating the digest
     */
    @Nonnull
    public static byte[] getKeyDigestMD5(@Nonnull Key k) throws IOException {
        return getKeyDigest(k, "MD5");
    }

    /**
     * Generates an digest from a Key object in the specified digest format. The supported digest formats will depend on
     * the JVM API.
     * 
     * @param k key to generate the digest from
     * @param dg digest format
     * @return the generated digest
     * @throws IOException if a problem exists creating the digest
     */
    @Nonnull
    public static byte[] getKeyDigest(@Nonnull Key k, @Nonnull String dg) throws IOException {
        try {
            MessageDigest md5 = MessageDigest.getInstance(dg);

            DigestInputStream in = new DigestInputStream(new ByteArrayInputStream(k.getEncoded()), md5);
            try {
                while (in.read(new byte[128]) > 0)
                    ; // simply discard the input
            } finally {
                in.close();
            }
            return md5.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    /**
     * Encode {@link byte[]} in hex formated string "ab:cd:ef:...:12"
     * 
     * @param data to be encoded
     * @return hex formated string "ab:cd:ef:...:12"
     */
    public static String hexEncode(byte[] data) {
        char[] hex = Hex.encodeHex(data);
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < hex.length; i += 2) {
            if (buf.length() > 0)
                buf.append(':');
            buf.append(hex, i, 2);
        }
        return buf.toString();
    }

    /**
     * Encodes a {@link byte[]} in base 64 string
     * 
     * @param data to be encoded
     * @return base 64 formatted string
     */
    public static String encodeBase64(byte[] data) {
        return new String(Base64.encode(data), StandardCharsets.UTF_8);
    }

    /**
     * Decodes a base 64 string into a {@link byte[]}
     * 
     * @param data to be decoded
     * @return decoded data
     */
    public static byte[] decodeBase64(String data) {
        return Base64.decode(data);
    }
}