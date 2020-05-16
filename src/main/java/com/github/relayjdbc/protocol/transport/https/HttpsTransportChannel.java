package com.github.relayjdbc.protocol.transport.https;

import com.github.relayjdbc.servlet.RequestEnhancer;
import com.github.relayjdbc.servlet.kryo.KryoRequestModifier;
import com.github.relayjdbc.protocol.transport.TransportChannel;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class HttpsTransportChannel implements TransportChannel {

	private static final String METHOD_POST = "POST";

	private final URL _url;
	private final RequestEnhancer _requestEnhancer;
	private final String _trustedFingerprint;

	private HttpURLConnection conn;

	private boolean installedCustomSSLSocketFactory = false;

	public HttpsTransportChannel(URL url, RequestEnhancer requestEnhancer, String _trustedFingerprint) {
		_url = url;
		_requestEnhancer = requestEnhancer;
		this._trustedFingerprint = _trustedFingerprint;
	}

	public InputStream sendAndWaitForResponse() throws IOException {
		if (conn == null) {
			throw new IllegalStateException("Not connected");
		}

		conn.connect();
		// check the response
		int responseCode = conn.getResponseCode();
		if (responseCode != HttpURLConnection.HTTP_OK) {
			throw new IOException("Unexpected server response: " + responseCode + " " + conn.getResponseMessage());
		}
		return conn.getInputStream();
	}

	public void open() throws IOException {
		if (this._trustedFingerprint != null) {
			if (!installedCustomSSLSocketFactory) {
				try {
					HttpsTransportTrustAll.trustDefaultButAlso(this._trustedFingerprint);
				} catch (Exception e) {
					e.printStackTrace();
				}
				installedCustomSSLSocketFactory = true;
			}
		}

		conn = (HttpURLConnection) _url.openConnection();
		conn.setDoOutput(true);
		conn.setDoInput(true);
		conn.setRequestMethod(METHOD_POST);
		conn.setAllowUserInteraction(false); // system may not ask the user
		conn.setUseCaches(false);
		conn.setInstanceFollowRedirects(false);
		conn.setRequestProperty("Content-type", "binary/x-java-serialized");

		// Finally let the optional Request-Enhancer set request properties
		if (_requestEnhancer != null) {
			_requestEnhancer.enhanceConnectRequest(new KryoRequestModifier(conn));
		}
	}

	public OutputStream getOutputStream() throws IOException {
		if (conn == null) {
			throw new IllegalStateException("Not connected");
		}
		return conn.getOutputStream();
	}

	@Override
	public void close() {
		if (conn != null) {
			conn.disconnect();
		}
	}
}
