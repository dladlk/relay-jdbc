package com.github.relayjdbc.protocol.transport.https;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class CustomSSLSocketFactory extends SSLSocketFactory {
	
	private static Log log = LogFactory.getLog(CustomSSLSocketFactory.class);

	private SSLSocketFactory socketFactory;

	private CustomTrustManager customTrustManager;

	public CustomSSLSocketFactory(String thumbprintsProperty) {
		try {
			long start = System.nanoTime();
			log.info("CustomSSLSocketFactory: start initialization of SSLSocket");
			SSLContext ctx = SSLContext.getInstance("TLSv1.2");
			log.info("CustomSSLSocketFactory: use protocol " + ctx.getProtocol());
			TrustManagerFactory defaultTrustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			KeyStore ks = null;
			/*
			 * Initi default factory with null ks - so default is used - otherwise exception thrown: TrustManagerFactoryImpl is not initialized
			 */
			defaultTrustManagerFactory.init(ks);
			TrustManager[] defaultTrustManagers = defaultTrustManagerFactory.getTrustManagers();

			X509TrustManager defaultTrustManager = null;
			if (defaultTrustManagers != null && defaultTrustManagers.length > 0) {
				/*
				 * Only first trust manager is used by SSLContext.init - so we take also only the first non null which implements X509TrustManager
				 */
				for (TrustManager trustManager : defaultTrustManagers) {
					if (trustManager != null && trustManager instanceof X509TrustManager) {
						defaultTrustManager = (X509TrustManager) trustManager;
					}
				}
			}
			customTrustManager = new CustomTrustManager(defaultTrustManager);

			if (thumbprintsProperty != null) {
				String[] split = thumbprintsProperty.split("[,;\\s]");
				int count = 0;
				Set<String> foundThumbprints = new HashSet<String>();
				for (String string : split) {
					if (string.length() > 0) {
						if (string.length() == 40) {
							count++;
							customTrustManager.addTrustedThumbprint(string);
							foundThumbprints.add(string);
						} else {
							log.warn(String.format("CustomSSLSocketFactory: Given value of thumbprint is not valid - it should be 40 symbols length, but it is %s: %s, skipped", string.length(), string));
						}
					}
				}
				if (count > 0) {
					log.info(String.format("CustomSSLSocketFactory: %s trust server thumbprint(s) configured: %s", count, foundThumbprints));
				}
			}

			/*
			 * If null keyManagerList passed - default is used
			 */
			KeyManager[] keyManagerList = null;
			ctx.init(keyManagerList, new TrustManager[] { customTrustManager }, new SecureRandom());

			socketFactory = ctx.getSocketFactory();

			log.info(String.format("CustomSSLSocketFactory: SSLSocket is configured in %s ms", formatMsDurationByStartNano(start)));
		} catch (Exception ex) {
			throw new IllegalArgumentException(ex);
		}
	}

	static String formatMsDurationByStartNano(long start) {
		return String.format("%.2f", (System.nanoTime() - start) / 1000000.0);
	}

	@Override
	public String[] getDefaultCipherSuites() {
		return socketFactory.getDefaultCipherSuites();
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return socketFactory.getSupportedCipherSuites();
	}

	@Override
	public Socket createSocket(Socket socket, String string, int i, boolean bln) throws IOException {
		return socketFactory.createSocket(socket, string, i, bln);
	}

	@Override
	public Socket createSocket(String string, int i) throws IOException, UnknownHostException {
		return socketFactory.createSocket(string, i);
	}

	@Override
	public Socket createSocket(String string, int i, InetAddress ia, int i1) throws IOException, UnknownHostException {
		return socketFactory.createSocket(string, i, ia, i1);
	}

	@Override
	public Socket createSocket(InetAddress ia, int i) throws IOException {
		return socketFactory.createSocket(ia, i);
	}

	@Override
	public Socket createSocket(InetAddress ia, int i, InetAddress ia1, int i1) throws IOException {
		return socketFactory.createSocket(ia, i, ia1, i1);
	}

	public void addTrustedThumbprint(String thumbprint) {
		this.customTrustManager.addTrustedThumbprint(thumbprint);
	}

	public static String getThumbprint(X509Certificate cert) {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-1");
			byte[] der = cert.getEncoded();
			md.update(der);
			byte[] digest = md.digest();
			String digestHex = String.valueOf(Hex.encodeHex(digest));
			return digestHex.toLowerCase();
		} catch (Exception e) {
			return "Failed to calculate thumbprint for " + cert + ": " + e.getMessage();
		}
	}
}

class CustomTrustManager implements X509TrustManager {
	
	private static Log log = LogFactory.getLog(CustomTrustManager.class);

	private static final X509Certificate[] EMPTY_CERTIFICATES = new java.security.cert.X509Certificate[0];
	private Set<String> trustedThumbprintSet = new HashSet<String>();
	private X509TrustManager defaultTrustManager;

	public CustomTrustManager(X509TrustManager defaultTrustManager) {
		this.defaultTrustManager = defaultTrustManager;
	}

	void addTrustedThumbprint(String thumbprint) {
		if (thumbprint == null) {
			return;
		}
		trustedThumbprintSet.add(thumbprint.toLowerCase());
	}

	private String paramsString(X509Certificate[] xcs, String authType) {
		String certs = Arrays.stream(xcs).map(x -> x.getSubjectX500Principal().getName() + ": " + CustomSSLSocketFactory.getThumbprint(x)).collect(Collectors.joining(", "));
		return String.format("authType=%s, xcs=%s", authType, certs);
	}

	@Override
	public void checkClientTrusted(X509Certificate[] xcs, String authType) throws CertificateException {
		log.debug(String.format("CustomTrustManager.checkServerTrusted: %s", paramsString(xcs, authType)));
	}

	@Override
	public void checkServerTrusted(X509Certificate[] xcs, String authType) throws CertificateException {
		if (xcs != null && !trustedThumbprintSet.isEmpty()) {
			boolean allMatched = true;
			for (X509Certificate x509Certificate : xcs) {
				String thumbprint = CustomSSLSocketFactory.getThumbprint(x509Certificate);
				if (trustedThumbprintSet.contains(thumbprint)) {
					log.debug(String.format("LDAPS server certificate %s is trusted because of configured thumbprint %s", x509Certificate.getSubjectX500Principal().getName(), thumbprint));
				} else {
					log.info(String.format("LDAPS server certificate %s thumbprint %s is not present in configured thumbprints %s", x509Certificate.getSubjectX500Principal().getName(), thumbprint, this.trustedThumbprintSet));
					allMatched = false;
				}
			}
			if (allMatched) {
				return;
			}
		}
		log.warn(String.format("CustomTrustManager.checkServerTrusted: no trusted certificate thumbprint found in configured set %s among given: %s", this.trustedThumbprintSet, paramsString(xcs, authType)));
		if (this.defaultTrustManager != null) {
			log.warn(String.format("CustomTrustManager.checkServerTrusted: try default trust manager %s", this.defaultTrustManager));
			this.defaultTrustManager.checkClientTrusted(xcs, authType);
		} else {
			log.warn("CustomTrustManager.checkServerTrusted: trust certificate as no security is applied - neither trusted thumbprint matched nor default trust manager.");
		}
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		log.trace("CustomTrustManager.getAcceptedIssuers returns empty list of accepted issuers");
		return EMPTY_CERTIFICATES;
	}

}