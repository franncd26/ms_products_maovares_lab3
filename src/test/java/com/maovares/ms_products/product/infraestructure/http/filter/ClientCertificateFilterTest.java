package com.maovares.ms_products.product.infraestructure.http.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class ClientCertificateFilterTest {

    @Test
    void allowsRequestsWhenValidationIsDisabled() throws Exception {
        ClientCertificateFilter filter = new ClientCertificateFilter(false, "");
        MockHttpServletResponse response = execute(filter, null);

        assertEquals(200, response.getStatus());
    }

    @Test
    void rejectsRequestsWithoutCertificate() throws Exception {
        ClientCertificateFilter filter = new ClientCertificateFilter(true, "ABC123");
        MockHttpServletResponse response = execute(filter, null);

        assertEquals(403, response.getStatus());
    }

    @Test
    void rejectsInvalidCertificateData() throws Exception {
        ClientCertificateFilter filter = new ClientCertificateFilter(true, "ABC123");
        MockHttpServletResponse response = execute(filter, "not-base64");

        assertEquals(403, response.getStatus());
    }

    @Test
    void rejectsCertificateWithUnexpectedThumbprint() throws Exception {
        String encodedCertificate = loadEncodedCertificate();
        ClientCertificateFilter filter = new ClientCertificateFilter(true, "ABC123");
        MockHttpServletResponse response = execute(filter, encodedCertificate);

        assertEquals(403, response.getStatus());
    }

    @Test
    void allowsCertificateWithExpectedThumbprint() throws Exception {
        String encodedCertificate = loadEncodedCertificate();
        ClientCertificateFilter filter = new ClientCertificateFilter(
                true,
                calculateThumbprint(encodedCertificate));
        MockHttpServletResponse response = execute(filter, encodedCertificate);

        assertEquals(200, response.getStatus());
    }

    private MockHttpServletResponse execute(
            ClientCertificateFilter filter,
            String encodedCertificate) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/v1/products");
        if (encodedCertificate != null) {
            request.addHeader(ClientCertificateFilter.CLIENT_CERT_HEADER, encodedCertificate);
        }
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());
        return response;
    }

    private String loadEncodedCertificate() throws Exception {
        try (var input = getClass().getResourceAsStream("/apim-client-cert.pem")) {
            if (input == null) {
                throw new IllegalStateException("Test certificate was not found");
            }
            String pem = new String(input.readAllBytes(), StandardCharsets.US_ASCII);
            String base64 = pem.replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(base64);
            return Base64.getEncoder().encodeToString(der);
        }
    }

    private String calculateThumbprint(String encodedCertificate) throws Exception {
        byte[] der = Base64.getDecoder().decode(encodedCertificate);
        X509Certificate certificate = (X509Certificate) CertificateFactory
                .getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
        byte[] digest = MessageDigest.getInstance("SHA-1").digest(certificate.getEncoded());
        StringBuilder result = new StringBuilder(digest.length * 2);
        for (byte value : digest) {
            result.append(String.format("%02X", value));
        }
        return result.toString();
    }
}
