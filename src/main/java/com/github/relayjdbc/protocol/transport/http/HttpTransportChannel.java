package com.github.relayjdbc.protocol.transport.http;

import com.github.relayjdbc.servlet.RequestEnhancer;
import com.github.relayjdbc.servlet.kryo.KryoRequestModifier;
import com.github.relayjdbc.protocol.transport.TransportChannel;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class HttpTransportChannel implements TransportChannel {

    private static final String METHOD_POST = "POST";

    private final URL _url;
    private final RequestEnhancer _requestEnhancer;

    private HttpURLConnection conn;

    public HttpTransportChannel(URL url, RequestEnhancer requestEnhancer) {
        _url = url;
        _requestEnhancer = requestEnhancer;
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
