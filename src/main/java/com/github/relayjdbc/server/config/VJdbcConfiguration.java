package com.github.relayjdbc.server.config;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Root configuration class. Can be initialized with different input objects
 * or be built up programmatically.
 */
public class VJdbcConfiguration {
    private static Log _logger = LogFactory.getLog(VJdbcConfiguration.class);

    private static VJdbcConfiguration _singleton;
    private static final Object configurationSingletonLockObject = new Object();

    private OcctConfiguration _occtConfiguration = new OcctConfiguration();
    private RmiConfiguration _rmiConfiguration;
    protected List<ConnectionConfiguration> _connections = new ArrayList<ConnectionConfiguration>();
    private static boolean useStreamingResultSet = true;
    // used for testing purposes only, emulates ping time between client and server
    private long _emulatePingTime = 0L;

    /**
     * overrides the use of the StreamingResultSet to allow other types of
     * result set network transport.
     *
     * Don't call this method unless you are defining your own network
     * transport which has it own mechanism for transporting result sets
     */
    public static void setUseCustomResultSetHandling() {
        useStreamingResultSet = false;
    }

    public static boolean getUseCustomResultSetHandling() {
        return useStreamingResultSet;
    }


    /**
     * Initialization with pre-opened InputStream.
     * @param configResourceInputStream InputStream
     * @param configVariables configuration variables represented as Properties
     * @throws ConfigurationException if the configuration is invalid
     */
    public static void init(InputStream configResourceInputStream, Properties configVariables) throws ConfigurationException {
        synchronized (configurationSingletonLockObject) {
            if(_singleton != null) {
                _logger.warn("VJdbcConfiguration already initialized, init-Call is ignored");
            } else {
                _singleton = VJdbcConfigurationParser.parse(configResourceInputStream, configVariables);
            }
        }
    }

    /**
     * Accessor method to the configuration singleton.
     * @return Configuration object
     * @throws RuntimeException Thrown when accessing without being initialized
     * previously
     */
    public static VJdbcConfiguration singleton() {
        synchronized (configurationSingletonLockObject) {
            if(_singleton == null) {
                throw new RuntimeException("relayjdbc-configuration is not initialized !");
            }
            return _singleton;
        }
    }

    /**
     * Constructor. Can be used for programmatical building the Configuration object.
     */
    public VJdbcConfiguration() {
    }

    public OcctConfiguration getOcctConfiguration() {
        return _occtConfiguration;
    }

    public void setOcctConfiguration(OcctConfiguration occtConfiguration) {
        _occtConfiguration = occtConfiguration;
    }

    /**
     * Returns the RMI-Configuration.
     * @return RmiConfiguration object or null
     */
    public RmiConfiguration getRmiConfiguration() {
        return _rmiConfiguration;
    }

    /**
     * Sets the RMI-Configuration object.
     * @param rmiConfiguration RmiConfiguration object to be used.
     */
    public void setRmiConfiguration(RmiConfiguration rmiConfiguration) {
        _rmiConfiguration = rmiConfiguration;
    }

    /**
     * Returns a ConnectionConfiguration for a specific identifier.
     * @param name Identifier of the ConnectionConfiguration
     * @return ConnectionConfiguration or null
     */
    public ConnectionConfiguration getConnection(String name) {
        for(Iterator<ConnectionConfiguration> it = _connections.iterator(); it.hasNext();) {
            ConnectionConfiguration connectionConfiguration = (ConnectionConfiguration)it.next();
            if(connectionConfiguration.getId().equals(name)) {
                return connectionConfiguration;
            }
        }
        return null;
    }

    /**
     * Adds a ConnectionConfiguration.
     * @param connectionConfiguration the connection configuration to add
     * @throws ConfigurationException Thrown when the connection identifier already exists
     */
    public void addConnection(ConnectionConfiguration connectionConfiguration) throws ConfigurationException {
        if(getConnection(connectionConfiguration.getId()) == null) {
            _connections.add(connectionConfiguration);
        } else {
            String msg = "Connection configuration for " + connectionConfiguration.getId() + " already exists";
            _logger.error(msg);
            throw new ConfigurationException(msg);
        }
    }

    void validateConnections() throws ConfigurationException {
        // Call the validation method of the configuration
        for(Iterator<ConnectionConfiguration> it = _connections.iterator(); it.hasNext();) {
            ConnectionConfiguration connectionConfiguration = (ConnectionConfiguration)it.next();
            connectionConfiguration.validate();
        }
    }

    void log() {
        if(_rmiConfiguration != null) {
            _rmiConfiguration.log();
        }
        _occtConfiguration.log();
        for(Iterator<ConnectionConfiguration> it = _connections.iterator(); it.hasNext();) {
            ConnectionConfiguration connectionConfiguration = (ConnectionConfiguration)it.next();
            connectionConfiguration.log();
        }
    }

	public long getEmulatePingTime() {
		return _emulatePingTime;
	}

	public void setEmulatePingTime(long emulatePingTime) {
		this._emulatePingTime = emulatePingTime;
	}

	public List<ConnectionConfiguration> getConnections() {
		return this._connections;
	}
}
