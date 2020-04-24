package com.github.relayjdbc.server;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Input;
import com.github.relayjdbc.VJdbcException;
import com.github.relayjdbc.RelayJdbcProperties;
import com.github.relayjdbc.command.Command;
import com.github.relayjdbc.command.ConnectionContext;
import com.github.relayjdbc.serial.CallingContext;
import com.github.relayjdbc.server.command.CommandProcessor;
import com.github.relayjdbc.server.config.ConnectionConfiguration;
import com.github.relayjdbc.server.config.VJdbcConfiguration;
import com.github.relayjdbc.server.servlet.KryoServletCommandSink;
import com.github.relayjdbc.protocol.ProtocolConstants;
import com.github.relayjdbc.util.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.InputStream;
import java.io.OutputStream;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;

public class CommandDispatcher {

    private static Log logger = LogFactory.getLog(CommandDispatcher.class);

    private final CommandProcessor commandProcessor;

    public CommandDispatcher(CommandProcessor processor) {
        this.commandProcessor = processor;
    }

    public void dispatch(InputStream inputStream, OutputStream os) {
        logger.info("dispatch requested");

        Kryo kryo = null;
        try (DeflatingOutput output = new DeflatingOutput(os);
             Input input = new InflatingInput(inputStream);) {

            kryo = KryoFactory.getInstance().getKryo();

            Object objectToReturn = dispatchCommandInternal(kryo, output, input);

            kryo.writeClassAndObject(output, objectToReturn);
            output.flush();

        } finally {
            if (kryo != null) {
                KryoFactory.getInstance().releaseKryo(kryo);
            }
        }
    }

    private Object dispatchCommandInternal(Kryo kryo, DeflatingOutput output, Input input) {
        try {
            checkMessageHeader(input, kryo);

            String method = kryo.readObject(input, String.class);
            logger.info("Method: " + method);

            if (method == null) {
                throw new IllegalStateException("method is null");
            }

            switch (method) {
                case ProtocolConstants.PROCESS_OPERATION:
                    return dispatchProcess(kryo, input, output);

                case ProtocolConstants.CONNECT_OPERATION:
                    return dispatchConnect(kryo, input);

                default:
                    throw new IllegalStateException("Unknown method: " + method);
            }
        } catch (Throwable t) {
            // Wrap any Throwable so that it can be transported back to the client
            return SQLExceptionHelper.wrap(t);
        }
    }

    private void checkMessageHeader(Input input, Kryo kryo) {
        try {
            String magic = kryo.readObject(input, String.class);
            if (!ProtocolConstants.MAGIC.equals(magic)) {
                logger.warn("DataFormat error: magic not found, but was: " + magic);
                throw new RuntimeException("DataFormat error: magic not found, but was: " + magic);
            }

            String clientVersion = kryo.readObject(input, String.class);
            if (!KryoServletCommandSink.PROTOCOL_VERSION.equals(clientVersion)) {
                String errorMsg = String.format("DataFormat version mismatch: expected %s but was %s",
                        KryoServletCommandSink.PROTOCOL_VERSION, clientVersion);
                logger.warn(errorMsg);
                throw new RuntimeException(errorMsg);
            }
        } catch (Exception ex) {
            logger.warn("Handshake failed", ex);
            throw new RuntimeException("DataFormat error: Handshake failed", ex);
        }

        logger.info("header OK");

    }

    private Object dispatchProcess(Kryo kryo, Input input, DeflatingOutput output) throws SQLException {
        logger.info("dispatchProcess");

        // Read parameter objects
        Long connuid = kryo.readObjectOrNull(input, Long.class);
        Long uid = kryo.readObjectOrNull(input, Long.class);
        Command cmd = (Command) kryo.readClassAndObject(input);
        CallingContext ctx = kryo.readObjectOrNull(input, CallingContext.class);
        if (connuid != null) {
            ConnectionContext connectionEntry = commandProcessor.getConnectionEntry(connuid);
            if (connectionEntry != null) {
                output.setCompressionMode(connectionEntry.getCompressionMode());
                output.setThreshold(connectionEntry.getCompressionThreshold());
            }
        }
        // Delegate execution to the CommandProcessor
        return commandProcessor.process(connuid, uid, cmd, ctx);
    }

    private Object dispatchConnect(Kryo kryo, Input input) throws SQLException, VJdbcException {
        logger.info("dispatchConnect");

        String url = kryo.readObject(input, String.class);
        Properties props = kryo.readObject(input, Properties.class);
        Properties clientInfo = kryo.readObject(input, Properties.class);
        CallingContext ctx = kryo.readObjectOrNull(input, CallingContext.class);

        ConnectionConfiguration connectionConfiguration = getConnectionConfiguration(url);

        if (connectionConfiguration == null) {
            return new SQLException("Relay Connection '" + url + "' not found");
        }

        Connection conn = connectionConfiguration.create(props);
        Object userName = props.get(RelayJdbcProperties.USER_NAME);
        if (userName != null) {
            clientInfo.put(RelayJdbcProperties.USER_NAME, userName);
        }
        return commandProcessor.registerConnection(conn, connectionConfiguration, clientInfo, ctx);


    }

	protected ConnectionConfiguration getConnectionConfiguration(String url) {
		return VJdbcConfiguration.singleton().getConnection(url);
	}


}
