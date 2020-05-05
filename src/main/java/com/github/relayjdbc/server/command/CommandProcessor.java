package com.github.relayjdbc.server.command;

import static com.github.relayjdbc.util.SQLExceptionHelper.CONNECTION_DOES_NOT_EXIST_STATE;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.github.relayjdbc.Registerable;
import com.github.relayjdbc.VJdbcException;
import com.github.relayjdbc.command.Command;
import com.github.relayjdbc.command.ConnectionContext;
import com.github.relayjdbc.command.DestroyCommand;
import com.github.relayjdbc.command.PingCommand;
import com.github.relayjdbc.command.StatementCancelCommand;
import com.github.relayjdbc.serial.CallingContext;
import com.github.relayjdbc.serial.UIDEx;
import com.github.relayjdbc.server.config.ConnectionConfiguration;
import com.github.relayjdbc.server.config.OcctConfiguration;
import com.github.relayjdbc.server.config.VJdbcConfiguration;
import com.github.relayjdbc.util.PerformanceConfig;
import com.github.relayjdbc.util.SQLExceptionHelper;

/**
 * The CommandProcessor is a singleton class which dispatches calls from the
 * client to the responsible connection object.
 */
public class CommandProcessor {
    private static Log _logger = LogFactory.getLog(CommandProcessor.class);

    private static boolean closeConnectionsOnKill = true;
    private Timer _timer = null;
    protected Map<Long, ConnectionEntry> _connectionEntries = new ConcurrentHashMap<Long, ConnectionEntry>();
    private OcctConfiguration _occtConfig;

    public static CommandProcessor getInstance() {
        return LazyHolder.INSTANCE;
    }

    private static final class LazyHolder {
        private static final CommandProcessor INSTANCE = initializeCommandProcessor();

        private static CommandProcessor initializeCommandProcessor() {
            CommandProcessor commandProcessor = new CommandProcessor();
            installShutdownHook(commandProcessor);

            return commandProcessor;
        }

        private static void installShutdownHook(CommandProcessor instance) {
            // Install the shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
                public void run() {
                    instance.destroy();
                }
            }));
        }
    }


    public static void setDontCloseConnectionsOnKill()
    {
        closeConnectionsOnKill = false;
    }

    protected CommandProcessor() {
        this(VJdbcConfiguration.singleton());
    }

    protected CommandProcessor(VJdbcConfiguration configuration) {
    	scheduleOCCT(configuration);
    }

	private void scheduleOCCT(VJdbcConfiguration configuration) {
		_occtConfig = configuration.getOcctConfiguration();
		if(_occtConfig.getCheckingPeriodInMillis() > 0) {
            _logger.debug("OCCT starts");

            _timer = new Timer(true);
            _timer.scheduleAtFixedRate(new OrphanedConnectionCollectorTask(), _occtConfig.getCheckingPeriodInMillis(), _occtConfig
                    .getCheckingPeriodInMillis());
        } else {
            _logger.debug("OCCT is turned off");
        }
	}

	protected VJdbcConfiguration getConfiguration() {
		return VJdbcConfiguration.singleton();
	}


    public UIDEx createConnection(String url, Properties props, Properties clientInfo, CallingContext ctx) throws SQLException {
        ConnectionConfiguration connectionConfiguration = getConfiguration().getConnection(url);

        if(connectionConfiguration != null) {
            _logger.debug("Found connection configuration " + connectionConfiguration.getId());

            Connection conn;
            try {
                conn = connectionConfiguration.create(props);
            } catch (VJdbcException e) {
                throw SQLExceptionHelper.wrap(e);
            }

            _logger.debug("Created connection, registering it now ...");

            UIDEx reg = registerConnection(conn, connectionConfiguration, clientInfo, ctx);

            if(_logger.isDebugEnabled()) {
                _logger.debug("Registered " + conn.getClass().getName() + " with UID " + reg);
            }

            return reg;
        } else {
            throw new SQLException("Can't find connection configuration for " + url);
        }
    }

    public ConnectionContext getConnectionEntry(Long connid) {
        if (connid!=null){
        	return _connectionEntries.get(connid);
        }
        return null;
    }

    public UIDEx registerConnection(Connection conn, ConnectionConfiguration config, Properties clientInfo, CallingContext ctx) {
        // To optimize the communication we can tell the client if
        // calling-contexts should be delivered at all
        int performanceProfile = PerformanceConfig.getPerformanceProfile(config.getCompressionModeAsInt(), config.getCompressionThreshold(), config.getRowPacketSize());
        UIDEx reg = new UIDEx(config.isTraceOrphanedObjects() ? 1 : 0, performanceProfile);
        _connectionEntries.put(reg.getUID(), buildConnectionEntry(conn, config, clientInfo, ctx, reg));
        return reg;
    }

	protected ConnectionEntry buildConnectionEntry(Connection conn, ConnectionConfiguration config, Properties clientInfo, CallingContext ctx, UIDEx reg) {
		return new ConnectionEntry(reg.getUID(), conn, config, clientInfo, ctx);
	}

    public void registerJDBCObject(Long connid, Registerable obj)
    {
    	ConnectionContext entry = getConnectionEntry(connid);
        assert(entry != null);
        entry.addJDBCObject(obj.getReg().getUID(), obj);
    }

    public void unregisterJDBCObject(Long connid, Registerable obj)
    {
    	ConnectionContext entry = getConnectionEntry(connid);
        if (entry != null) {
            entry.removeJDBCObject(obj.getReg().getUID());
        }
    }

    public void destroy() {
        _logger.debug("Destroying CommandProcessor ...");

        // Stop the timer
        if(_timer != null) {
            _timer.cancel();
        }

        if (closeConnectionsOnKill) {

            // Copy ConnectionEntries for closing
            ArrayList<ConnectionEntry> copyOfConnectionEntries = new ArrayList<ConnectionEntry>(_connectionEntries.values());
            // and clear the map immediately
            _connectionEntries.clear();

            for (ConnectionEntry connectionEntry: copyOfConnectionEntries){
				synchronized (connectionEntry) {
					connectionEntry.close();
				}
            }

        } else {
            _connectionEntries.clear();
        }

        _logger.debug("CommandProcessor successfully destroyed");
    }

    public Object process(Long connuid, Long uid, Command cmd, CallingContext ctx) throws SQLException {
        Object result = null;

		if (_logger.isInfoEnabled()) {
			_logger.info(String.format("%s%s: %s", connuid, uid != null ? "-" + uid : "", cmd));
		}

        if(connuid != null) {
            // Retrieving connection entry for the UID
            ConnectionEntry connentry = _connectionEntries.get(connuid);

            if(connentry != null) {
                try {
                    // StatementCancelCommand can be executed asynchronously to terminate
                    // a running query
                	if(cmd instanceof StatementCancelCommand) {
                        connentry.cancelCurrentStatementExecution(
                            connuid, uid, (StatementCancelCommand)cmd);
                    }
                    else {
                        // All other commands must be executed synchronously which is done
                        // by calling the synchronous executeCommand-Method
                        result = connentry.executeCommand(uid, cmd, ctx);
                    }
                } catch (SQLException e) {
                    if(_logger.isDebugEnabled()) {
                        _logger.debug("SQLException", e);
                    }
                    // Wrap the SQLException into something that can be safely thrown
                    throw SQLExceptionHelper.wrap(e);
                } catch (Throwable e) {
                    // Serious runtime error occured, wrap it in an SQLException
                    _logger.error("Unexpected",e);
                    throw SQLExceptionHelper.wrap(e);
                } finally {
                    // When there are no more JDBC objects left in the connection entry (that
                    // means even the JDBC-Connection is gone) the connection entry will be
                    // immediately destroyed and removed.
                    if(!connentry.hasJdbcObjects()) {
                        // As remove can be called asynchronously here, we must check the
                        // return value.
                        if(_connectionEntries.remove(connuid) != null) {
                            _logger.info("Connection " + connuid + " closed, statistics:");
                            connentry.traceConnectionStatistics();
                        }
                    }
                }
            } else {
                if(cmd instanceof DestroyCommand) {
                    _logger.debug("Connection entry already gone, DestroyCommand will be ignored");
                } else {
                    String msg = "Unknown connection entry " + connuid + " for command " + cmd.toString();
                    if (cmd instanceof PingCommand){
                    	_logger.info(msg);
                    } else {
                    	_logger.error(msg);
                    }
                    throw new SQLException(msg, CONNECTION_DOES_NOT_EXIST_STATE);
                }
            }
        } else {
            String msg = "Connection id is null";
            _logger.fatal(msg);
            throw new SQLException(msg);
        }

        return result;
    }

    /**
     * release all connections established by given user, except the given one.
     * @param connectionEntry the connection to release
     * @param userName the user name
     * @return number of released connections
     */
    public int releaseUserConnections(ConnectionContext connectionEntry, String userName)  {
    	int killedConnectionsCount = 0;
    	if (userName!=null){
    		_logger.debug("Killing connections for user "+userName);
//    		synchronized(_connectionEntries){
    			Iterator<Entry<Long, ConnectionEntry>> it = _connectionEntries.entrySet().iterator();
    			while (it.hasNext()){
    				Entry<Long, ConnectionEntry> me = it.next();
    				// do not use synchronized(ce) as it might deadlock, because connectionEntry is already locked
    				ConnectionEntry ce = me.getValue();
					if (ce!=connectionEntry && userName.equals(ce.getUserName())){    						
						_logger.info("Killing connection "+me.getKey()+" by request from user "+userName);
						ce.traceConnectionStatistics();
						ce.close();
						it.remove();
						killedConnectionsCount++;
					}
    			}    			
//    		}
    	}
    	return killedConnectionsCount;
    }
    
    /**
     * The orphaned connection collector task periodically checks the existing
     * connection entries for orphaned entries that means connections which
     * weren't used for a specific time and where the client didn't send keep
     * alive pings.
     */
    private class OrphanedConnectionCollectorTask extends TimerTask {
        public void run() {
            try {
                _logger.debug("Checking for orphaned connections ...");

                long millis = System.currentTimeMillis();

                for(Iterator<Long> it = _connectionEntries.keySet().iterator(); it.hasNext();) {
                    Long key = it.next();
                    ConnectionEntry connentry = _connectionEntries.get(key);

                    // Synchronize here so that the process-Method doesn't
                    // access the same entry concurrently
                    synchronized (connentry) {
                        long idleTime = millis - connentry.getLastAccess();

                        if(!connentry.isActive() && (idleTime > _occtConfig.getTimeoutInMillis())) {
                            _logger.info("Closing orphaned connection " + key + " after being idle for about " + (idleTime / 1000) + "sec");
                            connentry.traceConnectionStatistics();
                            // The close method doesn't throw an exception
                            connentry.close();
                            it.remove();
                        }
                    }
                }
            } catch (ConcurrentModificationException e) {
                // This exception might happen when the process-Method has changed the
                // connection-entry map while this iteration is ongoing. We just ignore the
                // exception and let the entry stay in the map until the next run of the
                // OCCT (the last access time isn't modified until the next run).
                if(_logger.isDebugEnabled()) {
                    String msg = "ConcurrentModificationException in OCCT";
                    _logger.debug(msg, e);
                }
            } catch (RuntimeException e) {
                // Any other error will be propagated so that the timer task is stopped
                String msg = "Unexpected Runtime-Exception in OCCT";
                _logger.fatal(msg, e);
            }
        }
    }
}
