package com.github.relayjdbc.client;

import com.github.relayjdbc.RelayJdbcProperties;
import com.github.relayjdbc.VirtualConnection;
import com.github.relayjdbc.command.*;
import com.github.relayjdbc.connectiontypes.ConnectionType;
import com.github.relayjdbc.connectiontypes.ConnectionTypeHandler;
import com.github.relayjdbc.serial.CallingContext;
import com.github.relayjdbc.serial.UIDEx;
import com.github.relayjdbc.util.ClientInfo;

import net.truedevelop.relayjdbc.RelayDriver;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.sql.Connection;
import java.util.Properties;

public final class ConnectionFactory {

    // The value 1 signals that every remote call shall provide a calling context. This should only
    // be used for debugging purposes as sending of these objects is quite expensive.
    private static final int REQUEST_PROVIDE_CALL_CONTEXT = 1;

    private static Log _logger = LogFactory.getLog(ConnectionFactory.class);

    public Connection getConnection(String relayUrl, Properties props) throws Exception {
        CommandSink sink;

        ConnectionType connectionType = ConnectionType.fromRelayUrl(relayUrl);
        if (connectionType == null) {
            throw new IllegalArgumentException("No connection type found for URL: " + relayUrl);
        }

        ConnectionTypeHandler connectionTypeHandler = connectionType.getConnectionTypeHandler();
        String dataSourceName = connectionTypeHandler.getDataSourceName(relayUrl);

        sink = connectionTypeHandler.getCommandSink(relayUrl, props);

        if(dataSourceName.length() > 0) {
            _logger.info("Connecting to datasource " + dataSourceName);
        } else {
            _logger.info("Using default datasource");
        }

        // Connect with the sink
        UIDEx reg = sink.connect(
                dataSourceName,
                props,
                ClientInfo.getProperties(props.getProperty(RelayJdbcProperties.CLIENTINFO_PROPERTIES)),
                new CallingContext());

        CallingContextFactory ctxFactory;
        if(reg.getValue1() == REQUEST_PROVIDE_CALL_CONTEXT) {
            ctxFactory = new StandardCallingContextFactory();
        }
        else {
            ctxFactory = new NullCallingContextFactory();
        }

        DecoratedCommandSink decoratedCommandSink = new DecoratedCommandSink(reg, sink, ctxFactory);

        return new VirtualConnection(reg, decoratedCommandSink, props, RelayDriver.isCacheEnabled());
    }
}
