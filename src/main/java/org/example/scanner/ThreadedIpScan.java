package org.example.scanner;

import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;

import java.io.IOException;
import java.net.InetAddress;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class ThreadedIpScan extends Thread{
    private static final String PEER_CERTIFICATES = "PEER_CERTIFICATES";
    private final CloseableHttpClient httpClient;
    private final RequestConfig requestConfig;
    private final List<String> ips;
    private List<String> domains;
    private int scansFinishedCount = 0;

    public ThreadedIpScan(CloseableHttpClient httpClient, RequestConfig requestConfig, List<String> ips){
        this.httpClient = httpClient;
        this.requestConfig = requestConfig;
        this.ips = ips;
    }

    @Override
    public void run(){
        domains=new ArrayList<String>();
        // scan for every ip
        for (String ip : ips) {
            try {
                scansFinishedCount++;
                // creating request
                HttpGet httpget = new HttpGet("https://" + ip);
                // time out config
                httpget.setConfig(requestConfig);
                // creating context where we would write certificates with interceptor
                HttpContext context = new BasicHttpContext();
                httpClient.execute(httpget, context);

                // get certificates
                Certificate[] peerCertificates = (Certificate[]) context.getAttribute(PEER_CERTIFICATES);
                for (Certificate certificate : peerCertificates) {
                    // get X509Certificate instance
                    X509Certificate real = (X509Certificate) certificate;
                    // other domains
                    Collection<List<?>> subjectAlternativeNames = real.getSubjectAlternativeNames();
                    // write in file
                    if (subjectAlternativeNames != null)
                        for (List<?> san : subjectAlternativeNames) {
                            if (san.get(0).equals(2)) {
                                domains.add(san.get(1).toString());
                                System.out.println("Domain: " + san.get(1));
                            }
                        }
                }
            }
            catch (ConnectTimeoutException e){
                System.out.println(ip + ": Connection timeout");
            } catch (Exception e) {
                System.out.println(ip + ": "+e.getMessage());
            }
        }
    }

    public List<String> getDomains() {
        return domains;
    }

    public int getScansFinishedCount() {
        return scansFinishedCount;
    }
}
