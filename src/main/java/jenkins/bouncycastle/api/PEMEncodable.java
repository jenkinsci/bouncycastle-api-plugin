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

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.encoders.Base64;

/**
 * A class that provides an API to manager PEM format, providing additional methods to handle Keys, Certificates,
 * Fingerprints, etc The supported algorithms will depend on the underlying version of BouncyCastle
 *
 * @since 1.0
 */
public final class PEMEncodable {

    /**
     * Stores the internal Bouncy Castle or JCA object
     */
    @Nonnull
    private Object object;

    private PEMEncodable(@Nonnull Object pemObject) {
        this.object = pemObject;
    }

    /**
     * Creates a {@link PEMEncodable} from a {@link Key} object
     * 
     * @param key {@link Key} object with the key
     * @return {@link PEMEncodable} object
     */
    @Nonnull
    public static PEMEncodable create(@Nonnull Key key) {
        return new PEMEncodable(key);
    }

    /**
     * Creates a {@link PEMEncodable} from a {@link KeyPair} object
     * 
     * @param keyPair {@link KeyPair} object with the key pair
     * @return {@link PEMEncodable} object
     */
    @Nonnull
    public static PEMEncodable create(@Nonnull KeyPair keyPair) {
        return new PEMEncodable(keyPair);
    }

    /**
     * Creates a {@link PEMEncodable} from a {@link Certificate} object
     * 
     * @param certificate {@link Certificate} object with the certificate
     * @return {@link PEMEncodable} object
     */
    @Nonnull
    public static PEMEncodable create(@Nonnull Certificate certificate) {
        return new PEMEncodable(certificate);
    }

    /**
     * Creates a {@link PEMEncodable} by decoding PEM formated data from a {@link String}
     * 
     * @param pem {@link String} with the PEM data
     * @return {@link PEMEncodable} object
     * @throws IOException launched if a problem exists reading the PEM information
     * @throws UnrecoverableKeyException in case PEM is passphrase protected and none or wrong is provided
     */
    @Nonnull
    public static PEMEncodable decode(@Nonnull String pem) throws IOException, UnrecoverableKeyException {
        return decode(pem, null);
    }

    /**
     * Creates a {@link PEMEncodable} by decoding PEM formated data from a {@link String}
     * 
     * @param pem {@link String} with the PEM data
     * @param passphrase passphrase for the encrypted PEM data. null if PEM data is not passphrase protected. The caller
     * is responsible for zeroing out the char[] after use to ensure the password does not stay in memory, e.g. with
     * <code>Arrays.fill(passphrase, (char)0)</code>
     * @return {@link PEMEncodable} object
     * @throws IOException launched if a problem exists reading the PEM information
     * @throws UnrecoverableKeyException in case PEM is passphrase protected and none or wrong is provided
     */
    @Nonnull
    public static PEMEncodable decode(@Nonnull String pem, @Nullable final char[] passphrase)
            throws IOException, UnrecoverableKeyException {

        try (PEMParser parser = new PEMParser(new StringReader(pem));) {

            Object object = parser.readObject();

            JcaPEMKeyConverter kConv = new JcaPEMKeyConverter().setProvider("BC");

            // handle supported PEM formats.
            if (object instanceof PEMEncryptedKeyPair) {
                if (passphrase != null) {
                    PEMDecryptorProvider dp = new JcePEMDecryptorProviderBuilder().build(passphrase);
                    PEMEncryptedKeyPair ekp = (PEMEncryptedKeyPair) object;
                    return new PEMEncodable(kConv.getKeyPair(ekp.decryptKeyPair(dp)));
                } else {
                    throw new UnrecoverableKeyException();
                }
            } else if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
                if (passphrase != null) {
                    InputDecryptorProvider dp = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(passphrase);
                    PKCS8EncryptedPrivateKeyInfo epk = (PKCS8EncryptedPrivateKeyInfo) object;
                    return new PEMEncodable(kConv.getPrivateKey(epk.decryptPrivateKeyInfo(dp)));
                } else {
                    throw new UnrecoverableKeyException();
                }
            } else if (object instanceof PEMKeyPair) {
                return new PEMEncodable(kConv.getKeyPair((PEMKeyPair) object));
            } else if (object instanceof PrivateKeyInfo) {
                return new PEMEncodable(kConv.getPrivateKey((PrivateKeyInfo) object));
            } else if (object instanceof SubjectPublicKeyInfo) {
                return new PEMEncodable(kConv.getPublicKey((SubjectPublicKeyInfo) object));
            } else if (object instanceof X509CertificateHolder) {
                JcaX509CertificateConverter cConv = new JcaX509CertificateConverter().setProvider("BC");
                return new PEMEncodable(cConv.getCertificate((X509CertificateHolder) object));
            } else {
                throw new IOException(
                        "Could not parse PEM, only key pairs, private keys, public keys and certificates are supported. Received "
                                + object.getClass().getName());
            }
        } catch (OperatorCreationException e) {
            throw new IOException(e.getMessage(), e);
        } catch (PKCSException e) {
            LOGGER.log(Level.WARNING, "Could not read PEM encrypted information", e);
            throw new UnrecoverableKeyException();
        } catch (CertificateException e) {
            throw new IOException("Could not read certificate", e);
        }
    }

    /**
     * Encodes the current stored information in PEM format and returns it as a {@link String}
     * 
     * @return PEM encoded data
     * @throws IOException launched if a problem exists generating the PEM information
     */
    @Nonnull
    public String encode() throws IOException {
        StringWriter sw = new StringWriter();
        JcaPEMWriter w = new JcaPEMWriter(sw);
        try {
            w.writeObject(object);
        } finally {
            w.close();
        }
        return sw.toString();
    }

    /**
     * Creates a {@link PEMEncodable} by reading a PEM file
     * 
     * @param pemFile {@link File} pointing to the PEM file to read
     * @return {@link PEMEncodable} object
     * @throws IOException launched if a problem exists reading the PEM information or the {@link File}
     * @throws UnrecoverableKeyException in case PEM is passphrase protected and none or wrong is provided
     */
    @Nonnull
    public static PEMEncodable read(@Nonnull File pemFile) throws IOException, UnrecoverableKeyException {
        return read(pemFile, null);
    }

    /**
     * Creates a {@link PEMEncodable} by reading a PEM file
     * 
     * @param pemFile {@link File} pointing to the PEM file to read
     * @param passphrase passphrase for the encrypted PEM data. null if PEM data is not passphrase protected. The caller
     * is responsible for zeroing out the char[] after use to ensure the password does not stay in memory, e.g. with
     * <code>Arrays.fill(passphrase, (char)0)</code>
     * @return {@link PEMEncodable} object
     * @throws IOException launched if a problem exists reading the PEM information or the {@link File}
     * @throws UnrecoverableKeyException in case PEM is passphrase protected and none or wrong is provided
     */
    @Nonnull
    public static PEMEncodable read(@Nonnull File pemFile, @Nullable char[] passphrase)
            throws IOException, UnrecoverableKeyException {
        return decode(FileUtils.readFileToString(pemFile), passphrase);
    }

    /**
     * Writes the current stored information in PEM formated {@link File}
     * 
     * @param pemFile PEM {@link File} to read
     * 
     * @throws IOException launched if a problem exists generating the PEM information or writing the {@link File}
     */
    public void write(@Nonnull File pemFile) throws IOException {
        FileUtils.writeStringToFile(pemFile, encode());
    }

    /**
     * Obtain {@link KeyPair} object with the public and private key from the decoded PEM. No conversion is performed,
     * the read PEM must contain private and public key in order to obtain a {@link KeyPair} object, null will be
     * returned in all the other cases.
     * 
     * @return {@link KeyPair} object with public and private keys or null if the read PEM didn't contain private and
     * public keys.
     */
    @CheckForNull
    public KeyPair toKeyPair() {

        if (object instanceof KeyPair) {
            return (KeyPair) object;
        }
        return null;
    }

    /**
     * Obtain {@link PublicKey} object from the read PEM. If the PEM data contained other object type like
     * {@link KeyPair} or {@link Certificate}, the public key will be extracted from them.
     * 
     * @return {@link PublicKey} with the public key, null if a public key could not be obtained from the current data
     */
    @CheckForNull
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
    @CheckForNull
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
    @CheckForNull
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
     * passed to the {@link #PEMEncodable(Object pemObject)}, the returned object can be one of the following (not
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
    @CheckForNull
    public Object getRawObject() {
        return object;
    }

    /**
     * Obtains the fingerprint of the private key in the "ab:cd:ef:...:12" format, which basically is an SHA1 digest
     * from the key, encoded in hex format.
     * 
     * @return private key fingerprint in hex format "ab:cd:ef:...:12", null if the private key could not be obtained
     * from the current PEM data.
     */
    @CheckForNull
    public String getPrivateKeyFingerprint() {
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
     */
    @CheckForNull
    public String getPublicKeyFingerprint() {
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
     */
    @Nonnull
    public static byte[] getKeyDigestSHA1(@Nonnull Key k) {
        try {
            return getKeyDigest(k, "SHA1");
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(
                    "SHA1 algorithm support is mandated by Java Language Specification. See https://docs.oracle.com/javase/7/docs/api/java/security/MessageDigest.html");
        }
    }

    /**
     * Generates an MD5 digest from a Key object
     * 
     * @param k the key to generate the digest from
     * @return the generated digest
     */
    @Nonnull
    public static byte[] getKeyDigestMD5(@Nonnull Key k) {
        try {
            return getKeyDigest(k, "MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(
                    "MD5 algorithm support is mandated by Java Language Specification. See https://docs.oracle.com/javase/7/docs/api/java/security/MessageDigest.html");
        }
    }

    /**
     * Generates an digest from a Key object in the specified digest format. The supported digest formats will depend on
     * the JVM API.
     * 
     * @param k key to generate the digest from
     * @param algorithm digest format
     * @return the generated digest
     * @throws NoSuchAlgorithmException when provided digest algorithm is not available
     */
    @Nonnull
    public static byte[] getKeyDigest(@Nonnull Key k, @Nonnull String algorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.update(k.getEncoded());
        return md.digest();
    }

    /**
     * Encode {@link byte[]} in hex formated string "ab:cd:ef:...:12"
     * 
     * @param data to be encoded
     * @return hex formated string "ab:cd:ef:...:12"
     */
    @Nonnull
    private static String hexEncode(@Nonnull byte[] data) {
        char[] hex = Hex.encodeHex(data);
        StringBuilder buf = new StringBuilder(hex.length + Math.max(0, hex.length / 2 - 1));
        for (int i = 0; i < hex.length; i += 2) {
            if (i > 0) {
                buf.append(':');
            }
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
    @Nonnull
    private static String encodeBase64(@Nonnull byte[] data) {
        return new String(Base64.encode(data), StandardCharsets.UTF_8);
    }

    /**
     * Decodes a base 64 string into a {@link byte[]}
     * 
     * @param data to be decoded
     * @return decoded data
     */
    @Nonnull
    private static byte[] decodeBase64(@Nonnull String data) {
        return Base64.decode(data);
    }

    private static final Logger LOGGER = Logger.getLogger(PEMEncodable.class.getName());
}