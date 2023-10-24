package org.example.scanner;

import org.apache.http.HttpException;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.conn.ManagedHttpClientConnection;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;

import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.security.cert.Certificate;

public class SSLResponseInterceptor implements HttpResponseInterceptor {
    private static final String PEER_CERTIFICATES = "PEER_CERTIFICATES";
    @Override
    public void process(HttpResponse httpResponse, HttpContext httpContext) throws  IOException {
        ManagedHttpClientConnection routedConnection = (ManagedHttpClientConnection) httpContext.getAttribute(HttpCoreContext.HTTP_CONNECTION);
        SSLSession sslSession = routedConnection.getSSLSession();
        if (sslSession != null) {
            Certificate[] certificates = sslSession.getPeerCertificates();
            httpContext.setAttribute(PEER_CERTIFICATES, certificates);
        }
    }
}
