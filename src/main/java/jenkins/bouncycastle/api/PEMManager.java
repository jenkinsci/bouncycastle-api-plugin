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
import org.bouncycastle.openssl.PasswordException;
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
    private Object object;

    /**
     * Creates a {@link PEMManager} by reading a PEM file
     * 
     * @param pemFile {@link File} pointing to the PEM file to read
     * @throws IOException launched if a problem exists reading the PEM information or the {@link File}
     * @throws BCPasswordException in case PEM is passphrase protected and none or wrong is provided
     */
    public PEMManager(@Nonnull File pemFile) throws IOException {
        decodePEM(pemFile, null);
    }

    /**
     * Creates a {@link PEMManager} by reading a PEM file
     * 
     * @param pemFile {@link File} pointing to the PEM file to read
     * @param passphrase passphrase for the encrypted PEM data. null if PEM data is not passphrase protected
     * @throws IOException launched if a problem exists reading the PEM information or the {@link File}
     * @throws BCPasswordException in case PEM is passphrase protected and none or wrong is provided
     */
    public PEMManager(@Nonnull File pemFile, @Nullable String passphrase) throws IOException {
        decodePEM(pemFile, passphrase);
    }

    /**
     * Creates a {@link PEMManager} by reading PEM formated data from a {@link String}
     * 
     * @param pem {@link String} with the PEM data
     * @throws IOException launched if a problem exists reading the PEM information
     * @throws BCPasswordException in case PEM is passphrase protected and none or wrong is provided
     */
    public PEMManager(@Nonnull String pem) throws IOException {
        decodePEM(pem, null);
    }

    /**
     * Creates a {@link PEMManager} by reading PEM formated data from a {@link String}
     * 
     * @param pem {@link String} with the PEM data
     * @param passphrase passphrase for the encrypted PEM data. null if PEM data is not passphrase protected
     * @throws IOException launched if a problem exists reading the PEM information
     * @throws BCPasswordException in case PEM is passphrase protected and none or wrong is provided
     */
    public PEMManager(@Nonnull String pem, @Nullable String passphrase) throws IOException {
        decodePEM(pem, passphrase);
    }

    /**
     *
     * Creates a {@link PEMManager} from an {@link Object} that can be of any supported type by Bouncy Castle or JCA:
     * {@link Key}, {@link PrivateKey}, {@link KeyPair}, {@link Certificate}, etc.
     *
     * @param pemObject object to manage
     */
    public PEMManager(@Nonnull Object pemObject) {
        this.object = pemObject;
    }

    private void decodePEM(@Nonnull File pemFile, @Nullable String passphrase) throws IOException {
        decodePEM(FileUtils.readFileToString(pemFile), passphrase);
    }

    private void decodePEM(@Nonnull String pem, @Nullable final String passphrase) throws IOException {
        PasswordFinder pwf = null;
        if (passphrase != null) {
            pwf = new PasswordFinder() {
                @Override
                public char[] getPassword() {
                    return passphrase.toCharArray();
                }
            };
        }

        PEMReader parser = new PEMReader(new StringReader(pem), pwf);
        try {
            object = parser.readObject();
        } catch (PasswordException pwE) {
            throw new BCPasswordException(pwE);
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
            w.writeObject(object);
        } finally {
            w.close();
        }
        return sw.toString();
    }

    /**
     * Encodes the current stored information in PEM formated {@link File}
     * 
     * @param pemFile PEM {@link File} to read
     * 
     * @throws IOException launched if a problem exists generating the PEM information or writing the {@link File}
     */
    public void encodePEM(@Nonnull File pemFile) throws IOException {
        FileUtils.writeStringToFile(pemFile, encodePEM());
    }

    /**
     * Obtain {@link KeyPair} object with the public and private key from the read PEM. No conversion is performed, the
     * read PEM must contain private and public key in order to obtain a {@link KeyPair} object, null will be returned
     * in all the other cases.
     * 
     * @return {@link KeyPair} object with public and private keys or null if the read PEM didn't contain private and
     * public keys.
     */
    @Nullable
    public KeyPair toKeyPair() {
        if (object instanceof KeyPair) {
            return (KeyPair) object;
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
    public PublicKey toPublicKey() {
        if (object instanceof PublicKey) {
            return (PublicKey) object;
        } else if (object instanceof KeyPair) {
            return ((KeyPair) object).getPublic();
        } else if (object instanceof Certificate) {
            return ((Certificate) object).getPublicKey();
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
    public Certificate toCertificate() {
        if (object instanceof Certificate) {
            return ((Certificate) object);
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
    public PrivateKey toPrivateKey() {
        if (object instanceof PrivateKey) {
            return (PrivateKey) object;
        } else if (object instanceof KeyPair) {
            return ((KeyPair) object).getPrivate();
        }
        return null;
    }

    /**
     * Obtains raw JCA or BouncyCastle {@link Object} from the read PEM. Depending on the PEM nature or the object
     * passed to the {@link #PEMManager(Object pemObject)}, the returned object can be one of the following (not
     * exhaustive list) and any classes that inherit from them:
     * <ul>
     * <li><strong>JCA</strong>
     * <ul>
     * <li>{@link Certificate}
     * <li>{@link java.security.cert.CRL}
     * <li>{@link KeyPair}
     * <li>{@link PublicKey}
     * <li>{@link PrivateKey}
     * </ul>
     * </ul>
     * <ul>
     * <li><strong>Bouncy Castle</strong>
     * <ul>
     * <li>{@link org.bouncycastle.asn1.cms.ContentInfo}
     * <li>{@link org.bouncycastle.jce.spec.ECNamedCurveParameterSpec}
     * <li>{@link org.bouncycastle.pkcs.PKCS10CertificationRequest}
     * <li>{@link org.bouncycastle.jce.provider.X509CertificateObject}
     * <li>{@link org.bouncycastle.x509.X509V2AttributeCertificate}
     * </ul>
     * </ul>
     * 
     * @return {@link Object} read from the PEM
     */
    @Nullable
    public Object getRawObject() {
        return object;
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
        PrivateKey key = toPrivateKey();
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
        PublicKey key = toPublicKey();
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
        try {
            return getKeyDigest(k, "SHA1");
        } catch (NoSuchAlgorithmException e) {
           throw new AssertionError("SHA1 algorithm not found to create digest");
        }
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
        try {
            return getKeyDigest(k, "MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("SHA1 algorithm not found to create digest");
        }
    }

    /**
     * Generates an digest from a Key object in the specified digest format. The supported digest formats will depend on
     * the JVM API.
     * 
     * @param k key to generate the digest from
     * @param algorithm digest format
     * @return the generated digest
     * @throws IOException if a problem exists creating the digest
     * @throws NoSuchAlgorithmException when provided digest algorithm is not available
     */
    @Nonnull
    public static byte[] getKeyDigest(@Nonnull Key k, @Nonnull String algorithm) throws IOException, NoSuchAlgorithmException {
        MessageDigest md5 = MessageDigest.getInstance(algorithm);

        DigestInputStream in = new DigestInputStream(new ByteArrayInputStream(k.getEncoded()), md5);
        try {
            while (in.read(new byte[128]) > 0)
                ; // simply discard the input
        } finally {
            in.close();
        }
        return md5.digest();
    }

    /**
     * Encode {@link byte[]} in hex formated string "ab:cd:ef:...:12"
     * 
     * @param data to be encoded
     * @return hex formated string "ab:cd:ef:...:12"
     */
    @Nonnull
    public static String hexEncode(@Nonnull byte[] data) {
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