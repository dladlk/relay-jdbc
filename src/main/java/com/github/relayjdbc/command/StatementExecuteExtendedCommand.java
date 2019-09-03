// VJDBC - Virtual JDBC
// Written by Michael Link
// Website: http://vjdbc.sourceforge.net

package com.github.relayjdbc.command;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.sql.SQLException;
import java.sql.Statement;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.KryoSerializable;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;

public class StatementExecuteExtendedCommand implements Command,KryoSerializable {
    private static final long serialVersionUID = 3978992080531764787L;

    private String _sql;
    private int _autoGeneratedKeys;
    private int[] _columnIndexes;
    private String[] _columnNames;

    public StatementExecuteExtendedCommand() {
    }

    public StatementExecuteExtendedCommand(String sql, int autoGeneratedKeys) {
        _sql = sql;
        _autoGeneratedKeys = autoGeneratedKeys;
    }

    public StatementExecuteExtendedCommand(String sql, int[] columnIndexes) {
        _sql = sql;
        _columnIndexes = columnIndexes;
    }

    public StatementExecuteExtendedCommand(String sql, String[] columnNames) {
        _sql = sql;
        _columnNames = columnNames;
    }

    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeObject(_sql);
        out.writeInt(_autoGeneratedKeys);
        out.writeObject(_columnIndexes);
        out.writeObject(_columnNames);
    }

    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        _sql = (String) in.readObject();
        _autoGeneratedKeys = in.readInt();
        _columnIndexes = (int[])in.readObject();
        _columnNames = (String[])in.readObject();
    }

    public Object execute(Object target, ConnectionContext ctx) throws SQLException {
        String sql = ctx.resolveOrCheckQuery(_sql);
        // Now make the descision what call to execute
        if(_columnIndexes != null) {
            return Boolean.valueOf(((Statement)target).execute(sql, _columnIndexes));
        }
        else if(_columnNames != null) {
            return Boolean.valueOf(((Statement)target).execute(sql, _columnNames));
        }
        else {
            return Boolean.valueOf(((Statement)target).execute(sql, _autoGeneratedKeys));
        }
    }

    public String toString() {
        return "StatementUpdateExtendedCommand: " + _sql;
    }

	@Override
	public void write(Kryo kryo, Output output) {
		kryo.writeObjectOrNull(output, _sql, String.class);
		output.writeInt(_autoGeneratedKeys);
		kryo.writeObjectOrNull(output, _columnIndexes, int[].class);
		kryo.writeObjectOrNull(output, _columnNames, String[].class);
	}

	@Override
	public void read(Kryo kryo, Input input) {
		_sql = kryo.readObjectOrNull(input, String.class);
		_autoGeneratedKeys = input.readInt();
		_columnIndexes = kryo.readObjectOrNull(input, int[].class);
		_columnNames = kryo.readObjectOrNull(input, String[].class);
	}
}