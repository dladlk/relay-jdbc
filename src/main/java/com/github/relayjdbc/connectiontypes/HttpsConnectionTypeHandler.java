package com.github.relayjdbc.connectiontypes;

import java.net.URL;
import java.sql.DriverPropertyInfo;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.github.relayjdbc.RelayJdbcProperties;
import com.github.relayjdbc.protocol.transport.Transport;
import com.github.relayjdbc.protocol.transport.https.HttpsTransport;
import com.github.relayjdbc.servlet.RequestEnhancer;
import com.github.relayjdbc.servlet.RequestEnhancerFactory;
import com.github.relayjdbc.util.StringUtils;

class HttpsConnectionTypeHandler extends ConnectionTypeHandler {

	private static final String RELAYJDBC_HTTPS_TRUSTED_FINGERPRINT = "relayjdbc.https.trusted_fingerprint";

	public static final long serialVersionUID = 1;

	private static Log _logger = LogFactory.getLog(HttpsConnectionTypeHandler.class);

	HttpsConnectionTypeHandler() {
		super("https:");
	}

    @Override
    protected String[] splitToUrlAndDataSourceName(String url) {
        // our prefix is the same as the actual protocol used, so simply split
        // This allows the following URL format: jdbc:relayjdbc:https://localhost:8080#h2db
        return StringUtils.split(url);
    }

	protected Transport getTransport(String url, Properties props) throws Exception {
		RequestEnhancer requestEnhancer = null;

		String requestEnhancerFactoryClassName = props.getProperty(RelayJdbcProperties.SERVLET_REQUEST_ENHANCER_FACTORY);

		if (requestEnhancerFactoryClassName != null) {
			_logger.debug("Found RequestEnhancerFactory class: " + requestEnhancerFactoryClassName);
			Class<?> requestEnhancerFactoryClass = Class.forName(requestEnhancerFactoryClassName);
			RequestEnhancerFactory requestEnhancerFactory = (RequestEnhancerFactory) requestEnhancerFactoryClass.newInstance();
			_logger.debug("RequestEnhancerFactory successfully created");
			requestEnhancer = requestEnhancerFactory.create();
		}
		
		String trustedFingerprint = props.getProperty(RELAYJDBC_HTTPS_TRUSTED_FINGERPRINT);

		return new HttpsTransport(new URL(url), requestEnhancer, trustedFingerprint);
	}

	@Override
	public DriverPropertyInfo[] getJdbcDriverPropertyInfo(String relayUrl, Properties info) {
		DriverPropertyInfo requestEnhancerFactory = new DriverPropertyInfo(RelayJdbcProperties.SERVLET_REQUEST_ENHANCER_FACTORY, info.getProperty(RelayJdbcProperties.SERVLET_REQUEST_ENHANCER_FACTORY));
		requestEnhancerFactory.description = "Class name of an implementation of " + RequestEnhancerFactory.class.getName();

		DriverPropertyInfo trustedFingerprint = new DriverPropertyInfo(RELAYJDBC_HTTPS_TRUSTED_FINGERPRINT, "");
		trustedFingerprint.description = "HTTPS certificate fingerprint of trusted remote server, e.g. F64C2990D021ADE991A0F9608155DA57FFE47F94";
		
		return new DriverPropertyInfo[] { requestEnhancerFactory, trustedFingerprint };
	}

}
