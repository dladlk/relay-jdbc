package net.truedevelop.relayjdbc;

import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.util.Properties;
import java.util.logging.Logger;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.github.relayjdbc.Version;
import com.github.relayjdbc.client.ConnectionFactory;
import com.github.relayjdbc.connectiontypes.ConnectionType;
import com.github.relayjdbc.connectiontypes.ConnectionTypeHandler;
import com.github.relayjdbc.util.SQLExceptionHelper;

public class RelayDriver implements Driver {

    private static final String RELAY_DRIVER_JDBC_URL_PREFIX = "jdbc:relayjdbc:";

    private static Log log = LogFactory.getLog(RelayDriver.class);

    private static boolean cacheEnabled;

    static {
        try {
            DriverManager.registerDriver(new RelayDriver());
            log.info("RelayDriver JDBC-Driver successfully registered");
            try {
                Class.forName("org.hsqldb.jdbcDriver").newInstance();
                log.info("HSQL-Driver loaded, caching activated");
                cacheEnabled = true;
            } catch (ClassNotFoundException e) {
                log.info("Couldn't load HSQL-Driver, caching deactivated");
                cacheEnabled = false;
            } catch (RuntimeException e) {
                log.error("Unexpected exception occured on loading the HSQL-Driver");
                cacheEnabled = false;
            }
        } catch (Throwable t) {
            log.fatal("Couldn't register RelayDriver JDBC-Driver !", t);
            throw new RuntimeException("Couldn't register RelayDriver JDBC-Driver !", t);
        }
    }

    private final ConnectionFactory connectionFactory;

    public RelayDriver() {
        this(new ConnectionFactory());
    }

    RelayDriver(ConnectionFactory connectionFactory) {
        this.connectionFactory = connectionFactory;
    }

    public static boolean isCacheEnabled() {
        return cacheEnabled;
    }

    public Connection connect(String urlstr, Properties props) throws SQLException {
        if (!acceptsURL(urlstr)) {
            return null;
        }

        String relayUrl = getRelayUrl(urlstr);

        if (log.isInfoEnabled()) {
        	log.info("Relay-URL: " + relayUrl);
        }

        try {
            return connectionFactory.getConnection(relayUrl, props);
        } catch (Exception e) {
            log.error(e);
            throw SQLExceptionHelper.wrap(e);
        }
    }

    public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) throws SQLException {
        if (acceptsURL(url)) {
            String relayUrl = getRelayUrl(url);
            ConnectionType connectionType = ConnectionType.fromRelayUrl(relayUrl);
            if (connectionType != null) {
                // if there is such a connection type available, inquire it about the available options
                ConnectionTypeHandler connectionTypeHandler = connectionType.getConnectionTypeHandler();

                return connectionTypeHandler.getJdbcDriverPropertyInfo(relayUrl, info);
            }
        }
        // no details available for the URL supplied
        return new DriverPropertyInfo[0];
    }

    public boolean acceptsURL(String url) throws SQLException {
        return url.startsWith(RELAY_DRIVER_JDBC_URL_PREFIX);
    }

    private String getRelayUrl(String urlstr) {
        return urlstr.substring(RELAY_DRIVER_JDBC_URL_PREFIX.length());
    }

    public int getMajorVersion() {
        return Version.majorIntVersion;
    }

    public int getMinorVersion() {
        return Version.minorIntVersion;
    }

    public boolean jdbcCompliant() {
        return true;
    }

    /*
     * Keep parent logger from relayjdbc
     */
    public Logger getParentLogger() {
        return Logger.getLogger("com.github.relayjdbc");
    }	

}
