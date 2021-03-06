package com.github.relayjdbc.command;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.sql.SQLException;

public class PingCommand extends AbstractCommand {
    static final long serialVersionUID = 3340327873423851L;

    public static final PingCommand INSTANCE = new PingCommand(); 
    
    private static Log _logger = LogFactory.getLog(PingCommand.class);

    private PingCommand() {
    }

    public void writeExternal(ObjectOutput out) throws IOException {
    }

    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
    }

    public Object execute(Object target, ConnectionContext ctx) throws SQLException {
        if(_logger.isDebugEnabled()) {
            _logger.debug("Keep alive ping ...");
        }
//        KryoFactory.getInstance().dumpInstanceCount();
        return null;
    }

    public String toString() {
        return "PingCommand";
    }
}
