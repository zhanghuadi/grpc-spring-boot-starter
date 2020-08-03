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

package net.devh.boot.grpc.test.security;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import lombok.extern.slf4j.Slf4j;
import net.devh.boot.grpc.common.security.Keystore2PemProtocolResolver;
import net.devh.boot.grpc.test.config.BaseAutoConfiguration;
import net.devh.boot.grpc.test.config.ManualSecurityConfiguration;
import net.devh.boot.grpc.test.config.ServiceConfiguration;
import net.devh.boot.grpc.test.config.WithCertificateSecurityConfiguration;

@Slf4j
@SpringBootTest(properties = {
        "grpc.server.security.enabled=true",
        "grpc.server.security.certificateChain=keystore2pem:PKCS12:changeit:certificate-chain:server;file:src/test/resources/certificates/server.p12",
        "grpc.server.security.privateKey=keystore2pem:PKCS12:changeit:private-key:server;file:src/test/resources/certificates/server.p12",
        "grpc.server.security.trustCertCollection=keystore2pem:PKCS12:changeit:trusted;file:src/test/resources/certificates/server.p12",
        "grpc.server.security.clientAuth=REQUIRE",

        "grpc.client.GLOBAL.address=localhost:9090",
        "grpc.client.GLOBAL.security.authorityOverride=localhost",
        "grpc.client.GLOBAL.security.clientAuthEnabled=true",

        "grpc.client.test.security.certificateChain=keystore2pem:PKCS12:changeit:certificate-chain:client1;file:src/test/resources/certificates/client1.p12",
        "grpc.client.test.security.privateKey=keystore2pem:PKCS12:changeit:private-key:client1;file:src/test/resources/certificates/client1.p12",
        "grpc.client.test.security.trustCertCollection=keystore2pem:PKCS12:changeit:trusted;file:src/test/resources/certificates/client1.p12",

        "grpc.client.noPerm.security.certificateChain=keystore2pem:PKCS12:changeit:certificate-chain:client2;file:src/test/resources/certificates/client2.p12",
        "grpc.client.noPerm.security.privateKey=keystore2pem:PKCS12:changeit:private-key:client2;file:src/test/resources/certificates/client2.p12",
        "grpc.client.noPerm.security.trustCertCollection=keystore2pem:PKCS12:changeit:trusted;file:src/test/resources/certificates/client2.p12",
})
@SpringJUnitConfig(classes = {
        ManualSecurityWithKeystoreCertificateTest.Keystore2PemConfiguration.class,
        ServiceConfiguration.class,
        BaseAutoConfiguration.class,
        ManualSecurityConfiguration.class,
        WithCertificateSecurityConfiguration.class,
})
@DirtiesContext
public class ManualSecurityWithKeystoreCertificateTest extends AbstractSecurityTest {

    public ManualSecurityWithKeystoreCertificateTest() {
        log.info("--- ManualSecurityWithKeystoreCertificateTest ---");
    }

    @Configuration
    public static class Keystore2PemConfiguration {

        @Bean
        static Keystore2PemProtocolResolver keystore2PemProtocolResolver() {
            return new Keystore2PemProtocolResolver();
        }

    }

}
