package com.maovares.ms_products.product.infraestructure.http.filter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Locale;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@Order(2)
public class ClientCertificateFilter extends OncePerRequestFilter {

    static final String CLIENT_CERT_HEADER = "X-ARR-ClientCert";

    private final boolean validationEnabled;
    private final String expectedThumbprint;

    public ClientCertificateFilter(
            @Value("${client.certificate.validation.enabled:false}") boolean validationEnabled,
            @Value("${client.certificate.thumbprint:}") String expectedThumbprint) {
        this.validationEnabled = validationEnabled;
        this.expectedThumbprint = normalizeThumbprint(expectedThumbprint);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        if (!validationEnabled) {
            filterChain.doFilter(request, response);
            return;
        }

        if (!StringUtils.hasText(expectedThumbprint)) {
            log.error("Client certificate validation is enabled without an expected thumbprint");
            reject(response);
            return;
        }

        String encodedCertificate = request.getHeader(CLIENT_CERT_HEADER);
        if (!StringUtils.hasText(encodedCertificate)) {
            log.warn("Request rejected because the client certificate header is missing");
            reject(response);
            return;
        }

        try {
            X509Certificate certificate = parseCertificate(encodedCertificate);
            String actualThumbprint = calculateSha1Thumbprint(certificate);

            if (!MessageDigest.isEqual(
                    expectedThumbprint.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                    actualThumbprint.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
                log.warn("Request rejected because the client certificate thumbprint is not trusted");
                reject(response);
                return;
            }

            filterChain.doFilter(request, response);
        } catch (Exception exception) {
            log.warn("Request rejected because the client certificate is invalid: {}",
                    exception.getMessage());
            reject(response);
        }
    }

    private X509Certificate parseCertificate(String encodedCertificate) throws Exception {
        byte[] certificateBytes = Base64.getDecoder().decode(encodedCertificate);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certificateFactory.generateCertificate(
                new ByteArrayInputStream(certificateBytes));
    }

    private String calculateSha1Thumbprint(X509Certificate certificate) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-1").digest(certificate.getEncoded());
        StringBuilder thumbprint = new StringBuilder(digest.length * 2);
        for (byte value : digest) {
            thumbprint.append(String.format("%02X", value));
        }
        return thumbprint.toString();
    }

    static String normalizeThumbprint(String thumbprint) {
        if (thumbprint == null) {
            return "";
        }
        return thumbprint.replace(":", "")
                .replaceAll("\\s", "")
                .toUpperCase(Locale.ROOT);
    }

    private void reject(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"Client certificate required or invalid\"}");
    }
}
