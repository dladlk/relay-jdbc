package com.github.relayjdbc.command;

import com.github.relayjdbc.server.command.ResultSetHolder;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.sql.SQLException;

public class NextRowPacketCommand extends AbstractCommand {
    static final long serialVersionUID = -8463588846424302034L;

    public static final NextRowPacketCommand INSTANCE = new NextRowPacketCommand();

    private NextRowPacketCommand() {
    }

    public void writeExternal(ObjectOutput out) throws IOException {
    }

    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
    }

    public Object execute(Object target, ConnectionContext ctx) throws SQLException {
        ResultSetHolder rsh = (ResultSetHolder) target;
        // Return next serialized RowPacket
        return rsh.nextRowPacket();
    }

    public String toString() {
        return "NextRowPacketCommand";
    }
}
