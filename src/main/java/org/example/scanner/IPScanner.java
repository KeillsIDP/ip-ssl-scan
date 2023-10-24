package org.example.scanner;

import org.apache.commons.collections4.list.SetUniqueList;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContexts;

import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class IPScanner {
    private final CloseableHttpClient httpClient;
    private final RequestConfig requestConfig;

    public IPScanner() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        SSLConnectionSocketFactory scsf = new SSLConnectionSocketFactory(
                SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build(),
                NoopHostnameVerifier.INSTANCE);

        SSLResponseInterceptor interceptor = new SSLResponseInterceptor();
        PoolingHttpClientConnectionManager cm = new PoolingHttpClientConnectionManager();
        cm.setMaxTotal(100);
        // set time out here
        this.requestConfig = RequestConfig.custom()
                .setConnectTimeout(1000)
                .setSocketTimeout(1000)
                .setConnectionRequestTimeout(1000)
                .build();
        this.httpClient = HttpClients.custom().addInterceptorFirst(interceptor).setSSLSocketFactory(scsf).build();
    }

    public void terminateClient() throws IOException {
        httpClient.close();
    }

    public void scan(String ip,int threadsCount) throws InterruptedException {
        List<String> ips = getIps(ip);
        if(ips==null) {
            System.out.println("Incorrect ip");
            return;
        }
        // creating list of threads
        int overall = 0;
        List<ThreadedIpScan> threads = new ArrayList<ThreadedIpScan>();
        int n = ips.size()/threadsCount+1;
        for(int i = 0;i<threadsCount;i++){
            int rightBound = (i+1)*n;
            if(rightBound>ips.size())
                rightBound = ips.size();

            List<String> threadIps = ips.subList(i*n,rightBound);
            ThreadedIpScan thread = new ThreadedIpScan(httpClient,requestConfig,threadIps);
            threads.add(thread);

            if((i+1)*n >ips.size()-1)
                break;
        }
        ScanProgressThread scanThread = new ScanProgressThread(threads,ips.size());
        scanThread.run();
    }

    private List<String> getIps(String ipWithMask) {
        try {
            String[] parts = ipWithMask.split("/");
            String baseIP = parts[0];
            int subnetMask = Integer.parseInt(parts[1]);

            InetAddress inetAddress = InetAddress.getByName(baseIP);
            byte[] ipBytes = inetAddress.getAddress();

            int[] ip = new int[4];
            for (int i = 0; i < 4; i++) {
                ip[i] = ipBytes[i] & 0xFF;
            }

            int numberOfAddresses = (int) Math.pow(2, 32 - subnetMask);

            List<String> ips = new ArrayList<String>();

            for (int i = 0; i < numberOfAddresses; i++) {
                ips.add(ip[0] + "." + ip[1] + "." + ip[2] + "." + ip[3]);
                ip[3]++;
                for (int j = 3; j >= 0; j--) {
                    if (ip[j] > 255) {
                        ip[j] = 0;
                        ip[j - 1]++;
                    }
                }
            }
            return ips;
        } catch (UnknownHostException e) {
            System.out.println(e.getMessage());
            return null;
        }
    }
}
