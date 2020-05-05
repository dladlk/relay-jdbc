package com.github.relayjdbc.protocol.transport.https;

import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class HttpsTransportTrustAll {

	public static void trustDefaultButAlso(String thumbprintsProperty) throws Exception {
		HttpsURLConnection.setDefaultSSLSocketFactory(new CustomSSLSocketFactory(thumbprintsProperty));
		// Create all-trusting host name verifier
		HostnameVerifier localhostValid = new HostnameVerifier() {
			public boolean verify(String hostname, SSLSession session) {
	            if ("localhost".equals(hostname)) {
	                return true;
	            } else {
	                HostnameVerifier hv = HttpsURLConnection.getDefaultHostnameVerifier();
	                return hv.verify(hostname, session);
	            }
	           }
		};

		// Install the all-trusting host verifier
		 HttpsURLConnection.setDefaultHostnameVerifier(localhostValid);
	}

	public static void trustAll() throws Exception {
		TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			public void checkClientTrusted(X509Certificate[] certs, String authType) {
			}

			public void checkServerTrusted(X509Certificate[] certs, String authType) {
			}
		} };
		// Install the all-trusting trust manager
		SSLContext sc = SSLContext.getInstance("SSL");
		sc.init(null, trustAllCerts, new java.security.SecureRandom());
		HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

		// Create all-trusting host name verifier
		HostnameVerifier allHostsValid = new HostnameVerifier() {
			public boolean verify(String hostname, SSLSession session) {
				return true;
			}
		};

		// Install the all-trusting host verifier
		HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
	}
}