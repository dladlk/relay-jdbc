package com.github.relayjdbc.command;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.sql.Connection;
import java.sql.SQLException;

public class ConnectionCommitCommand extends AbstractCommand {
    static final long serialVersionUID = 6221665321426908025L;

    public static final ConnectionCommitCommand INSTANCE = new ConnectionCommitCommand();

    private ConnectionCommitCommand() {
    }

    public void writeExternal(ObjectOutput out) throws IOException {
    }

    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
    }

    public Object execute(Object target, ConnectionContext ctx) throws SQLException {
        Connection conn = (Connection)target;
        conn.commit();
        return (conn.getWarnings() != null) ? Boolean.TRUE : Boolean.FALSE;
    }

    public String toString() {
        return "ConnectionCommitCommand";
    }
}
