package com.github.relayjdbc.command;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.sql.SQLException;
import java.sql.Statement;

public class StatementUpdateCommand extends AbstractCommand implements ISqlCommand {
    private static final long serialVersionUID = 3689069560279937335L;

    private String _sql;

    public StatementUpdateCommand() {
    }

    public StatementUpdateCommand(String sql) {
        _sql = sql;
    }
    
    public String getValue() {
		return _sql;
	}

	public void writeExternal(ObjectOutput out) throws IOException {
        out.writeObject(_sql);
    }

    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        _sql = (String) in.readObject();
    }

    public Object execute(Object target, ConnectionContext ctx) throws SQLException {
        return Integer.valueOf(((Statement) target).executeUpdate(ctx.resolveOrCheckQuery(_sql)));
    }

    public String toString() {
        return "StatementUpdateCommand: " + _sql;
    }
    
	public String getSql() {
		return _sql;
	}
}
