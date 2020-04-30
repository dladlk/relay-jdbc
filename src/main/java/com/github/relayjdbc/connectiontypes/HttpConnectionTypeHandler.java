package com.github.relayjdbc.connectiontypes;

import com.github.relayjdbc.RelayJdbcProperties;
import com.github.relayjdbc.protocol.transport.Transport;
import com.github.relayjdbc.protocol.transport.http.HttpTransport;
import com.github.relayjdbc.servlet.RequestEnhancer;
import com.github.relayjdbc.servlet.RequestEnhancerFactory;
import com.github.relayjdbc.util.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.net.URL;
import java.sql.DriverPropertyInfo;
import java.util.Properties;

class HttpConnectionTypeHandler extends ConnectionTypeHandler {

    public static final long serialVersionUID = 1;

    private static Log _logger = LogFactory.getLog(HttpConnectionTypeHandler.class);

    HttpConnectionTypeHandler() {
        super("http:");
    }

    @Override
    protected String[] splitToUrlAndDataSourceName(String url) {
        // our prefix is the same as the actual protocol used, so simply split
        // This allows the following URL format: jdbc:relayjdbc:http://localhost:8080#h2db
        return StringUtils.split(url);
    }

    protected Transport getTransport(String url, Properties props) throws Exception {
        RequestEnhancer requestEnhancer = null;

        String requestEnhancerFactoryClassName =
                props.getProperty(RelayJdbcProperties.SERVLET_REQUEST_ENHANCER_FACTORY);

        if(requestEnhancerFactoryClassName != null) {
            _logger.debug("Found RequestEnhancerFactory class: " + requestEnhancerFactoryClassName);
            Class requestEnhancerFactoryClass = Class.forName(requestEnhancerFactoryClassName);
            RequestEnhancerFactory requestEnhancerFactory =
                    (RequestEnhancerFactory)requestEnhancerFactoryClass.newInstance();
            _logger.debug("RequestEnhancerFactory successfully created");
            requestEnhancer = requestEnhancerFactory.create();
        }

        return new HttpTransport(new URL(url), requestEnhancer);
    }

    @Override
    public DriverPropertyInfo[] getJdbcDriverPropertyInfo(String relayUrl, Properties info) {
        DriverPropertyInfo requestEnhancerFactory = new DriverPropertyInfo(
                RelayJdbcProperties.SERVLET_REQUEST_ENHANCER_FACTORY,
                info.getProperty(RelayJdbcProperties.SERVLET_REQUEST_ENHANCER_FACTORY));

        requestEnhancerFactory.description =
                "Class name of an implementation of " + RequestEnhancerFactory.class.getName();

        return new DriverPropertyInfo[] { requestEnhancerFactory };
    }

}
