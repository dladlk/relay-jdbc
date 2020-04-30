package com.github.relayjdbc.protocol.transport.https;

import java.io.IOException;
import java.net.URL;

import com.github.relayjdbc.protocol.transport.Transport;
import com.github.relayjdbc.protocol.transport.TransportChannel;
import com.github.relayjdbc.servlet.RequestEnhancer;

public class HttpsTransport implements Transport {

	private final URL _url;
	private final RequestEnhancer _requestEnhancer;
	private final String _trustedFingerprint;

	public HttpsTransport(URL url, RequestEnhancer requestEnhancer, String trustedFingerprint) {
		_url = url;
		_requestEnhancer = requestEnhancer;
		_trustedFingerprint = trustedFingerprint;
	}

	@Override
	public TransportChannel getTransportChannel() throws IOException {
		HttpsTransportChannel httpTransportChannel = new HttpsTransportChannel(_url, _requestEnhancer, _trustedFingerprint);

		return httpTransportChannel;
	}

	public void close() {
		// do nothing
	}
}
