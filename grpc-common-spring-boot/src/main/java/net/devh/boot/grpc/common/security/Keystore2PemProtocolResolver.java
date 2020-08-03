/*
 * Copyright (c) 2016-2020 Michael Zhang <yidongnan@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package net.devh.boot.grpc.common.security;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static java.util.Collections.emptySet;
import static java.util.Collections.singleton;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.UncheckedIOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.context.ResourceLoaderAware;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ProtocolResolver;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import com.google.common.collect.Iterables;

import lombok.extern.slf4j.Slf4j;

/**
 * A {@link Resource} {@link ProtocolResolver} that is able to convert a keystore to a pem on the fly.
 *
 * <p>
 * <b>Format:</b>
 * </p>
 *
 * <pre>
 * {@code keystore2pem:<KeyStoreFormat>:[KeyStorePassword]:<command>:...additionalParameters;<KeyStoreResourcePath>}
 * </pre>
 *
 * <p>
 * <b>Supported Commands:</b>
 * </p>
 *
 * <ul>
 * <li>Extract certificate chain
 *
 * <pre>
 * {@code keystore2pem:<KeyStoreFormat>:<KeyStorePassword>:certificate-chain:<KeyAlias>;<KeyStoreResourcePath>}
 * </pre>
 *
 * </li>
 * <li>Extract private key
 *
 * <pre>
 * {@code keystore2pem:<KeyStoreFormat>:<KeyStorePassword>:private-key:<KeyAlias>[:KeyPassword];<KeyStoreResourcePath>}
 * </pre>
 *
 * </li>
 * <li>Extract trusted certificates
 *
 * <pre>
 * {@code keystore2pem:<KeyStoreFormat>:<KeyStorePassword>:trusted;<KeyStoreResourcePath>}
 * </pre>
 *
 * </li>
 * </ul>
 *
 * <p>
 * <b>Note:</b> Requires {@code org.bouncycastle:bcpkix-jdk15on} as dependency.
 * </p>
 *
 * @author Daniel Theuke (daniel.theuke@heuboe.de)
 */
@Slf4j
public class Keystore2PemProtocolResolver implements ResourceLoaderAware, ProtocolResolver {

    static {
        // Required to load some private keys.
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String SCHEME = "keystore2pem:";

    @Override
    public void setResourceLoader(final ResourceLoader resourceLoader) {
        if (resourceLoader instanceof DefaultResourceLoader) {
            ((DefaultResourceLoader) resourceLoader).addProtocolResolver(this);
        } else {
            log.warn("Unable to register the '" + SCHEME + "' resource protocol to this kind of ResourceLoader: "
                    + "{} (not a DefaultResourceLoader)", resourceLoader);
        }
    }

    @Override
    public Resource resolve(final String location, final ResourceLoader resourceLoader) {
        if (location.startsWith(SCHEME)) {
            return resolveMatching(location, resourceLoader);
        }
        return null;
    }

    /**
     * Resolves the given location assuming that it matches the supported resource protocol.
     *
     * @param location The full location of the resource.
     * @param resourceLoader The resource loader used to load the keystore.
     * @return The resource containing the specified value(s) in pem format.
     */
    private Resource resolveMatching(final String location, final ResourceLoader resourceLoader) {
        try {
            final String subLocation = location.substring(SCHEME.length());
            final String[] parts = subLocation.split(";", 2);
            if (parts.length != 2) {
                throw malformed("Missing Resource Location: `;<resource location>`");
            }
            final String parameterString = parts[0];
            final Resource keystoreResource = resourceLoader.getResource(parts[1]);

            final String[] parameters = parameterString.split(":");

            final KeyStore keyStore = KeyStore.getInstance(parameters[0]);

            if (parameters.length < 2) {
                throw malformed("Missing keyStorePassword: `:[KeyStorePassword]:...`");
            }
            final char[] keyStorePassword = parameters[1].isEmpty() ? null : parameters[1].toCharArray();

            try (InputStream keyStoreStream = keystoreResource.getInputStream()) {
                keyStore.load(keyStoreStream, keyStorePassword);
            }

            return extract(keyStore, parameters);
        } catch (final Exception e) {
            throw new IllegalArgumentException("Failed to convert keystore to pem", e);
        }
    }

    /**
     * Creates an IllegalArgumentException for a malformed resource string.
     *
     * @param reason The reason, why it was malformed.
     * @return The newly created exception.
     */
    private IllegalArgumentException malformed(final String reason) {
        return new IllegalArgumentException(
                "Malformated resource string. Format: `" + SCHEME + "parameters;keystore-location`.\n" + reason);
    }

    /**
     * Extracts the requested value(s) from the given keystore.
     *
     * @param keyStore The keystore to extract it/them from.
     * @param parameters The parameters used.
     * @return The resource containing the requested value(s) in pem format.
     * @throws KeyStoreException If the keystore has not been initialized - Should never happen.
     * @throws NoSuchAlgorithmException If the algorithm for recovering the key cannot be found
     * @throws UnrecoverableKeyException If the key cannot be recovered (e.g., the given password is wrong).
     * @throws InvalidAlgorithmParameterException If the keystore does not contain at least one trusted certificate
     *         entry
     */
    private Resource extract(final KeyStore keyStore, final String[] parameters)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException,
            InvalidAlgorithmParameterException {

        if (parameters.length < 3) {
            throw malformed("Missing extractionMode: `:<extractionMode>...`");
        }
        final String extractionMode = parameters[2];
        switch (extractionMode) {
            case "certificate-chain":
                return extractCertificateChain(keyStore, parameters);

            case "private-key":
                return extractPrivateKey(keyStore, parameters);

            case "trusted":
                return extractTrusted(keyStore);

            default:
                throw malformed("Unknown extraction mode: " + extractionMode
                        + "; Expected either of: [certificate-chain, private-key, trusted]");
        }
    }

    /**
     * Extracts the certificate chain from the given keystore.
     *
     * @param keyStore The keystore to extract it/them from.
     * @param parameters The parameters used.
     *
     * @return The resource containing the certificate chain in pem format.
     * @throws KeyStoreException If the keystore has not been initialized - Should never happen.
     */
    private Resource extractCertificateChain(final KeyStore keyStore, final String[] parameters)
            throws KeyStoreException {

        if (parameters.length < 4) {
            throw malformed("Missing certificate-chain alias: `:<alias>;...`");
        } else if (parameters.length != 4) {
            throw malformed("Too many parameters for certificate-chain extraction. "
                    + "Got: " + parameters.length + "; Expected: 4");
        }

        final String alias = parameters[3];

        return toResource(keyStore.getCertificateChain(alias));
    }

    /**
     * Extracts the private key from the given keystore.
     *
     * @param keyStore The keystore to extract it from.
     * @param parameters The parameters used.
     *
     * @return The resource containing the private key in pem format.
     * @throws KeyStoreException If the keystore has not been initialized - Should never happen.
     * @throws NoSuchAlgorithmException If the algorithm for recovering the key cannot be found
     * @throws UnrecoverableKeyException If the key cannot be recovered (e.g., the given password is wrong).
     */
    private Resource extractPrivateKey(final KeyStore keyStore, final String[] parameters)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {

        if (parameters.length < 4) {
            throw malformed("Missing private-key alias: `:<alias>[:<key-password>];...`");
        } else if (parameters.length > 5) {
            throw malformed("Too many parameters for private-key extraction. "
                    + "Got: " + parameters.length + "; Expected: 5");
        }

        final String alias = parameters[3];
        final String password = parameters.length != 5 ? parameters[1] : parameters[4];
        final char[] passwordChars = password.isEmpty() ? null : password.toCharArray();

        return toResource(singleton(keyStore.getKey(alias, passwordChars)));
    }

    /**
     * Extracts the trusted certificates from the given keystore.
     *
     * @param keyStore The keystore to extract them from.
     * @return The resource containing the trusted certificates in pem format.
     * @throws KeyStoreException If the keystore has not been initialized - Should never happen.
     * @throws InvalidAlgorithmParameterException If the keystore does not contain at least one trusted certificate
     *         entry
     */
    private Resource extractTrusted(final KeyStore keyStore)
            throws KeyStoreException, InvalidAlgorithmParameterException {

        final PKIXParameters params = new PKIXParameters(keyStore);

        return toResource(Iterables.transform(params.getTrustAnchors(), TrustAnchor::getTrustedCert));
    }

    /**
     * Writes the given certificates as pem to an in memory resource.
     *
     * @param elements The certificates to write.
     * @return The Resource with the given certificates in pem format.
     */
    private Resource toResource(final Certificate... elements) {
        return toResource(elements == null ? emptySet() : asList(elements));
    }

    /**
     * Writes the given elements as pem to an in memory resource.
     *
     * @param elements The elements to write.
     * @return The Resource with the given elements in pem format.
     */
    private Resource toResource(final Iterable<?> elements) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            try (OutputStreamWriter ows = new OutputStreamWriter(bos, UTF_8);
                    PemWriter writer = new PemWriter(ows)) {
                for (final Object elem : elements) {
                    // No need to encrypt this, as this is only passed in memory
                    writer.writeObject(new JcaMiscPEMGenerator(elem));
                }
            }
            return new ByteArrayResource(bos.toByteArray());
        } catch (final IOException e) {
            throw new UncheckedIOException("Failed to convert certificates to pem format", e);
        }
    }

}
