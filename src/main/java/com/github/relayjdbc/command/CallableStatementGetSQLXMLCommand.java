// VJDBC - Virtual JDBC
// Written by Hunter Payne
// Website: http://vjdbc.sourceforge.net

package com.github.relayjdbc.command;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.sql.CallableStatement;
import java.sql.SQLException;
import java.sql.SQLXML;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.KryoSerializable;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;

import com.github.relayjdbc.serial.SerialSQLXML;

public class CallableStatementGetSQLXMLCommand extends AbstractCommand implements KryoSerializable {
    static final long serialVersionUID = 4203440656745793953L;

    private int _index;
    private String _parameterName;

    public CallableStatementGetSQLXMLCommand() {
    }

    public CallableStatementGetSQLXMLCommand(int index) {
        _index = index;
    }

    public CallableStatementGetSQLXMLCommand(String paramName) {
        _parameterName = paramName;
    }

    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(_index);
        out.writeObject(_parameterName);
    }

    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        _index = in.readInt();
        _parameterName = (String)in.readObject();
    }

    public Object execute(Object target, ConnectionContext ctx) throws SQLException {
        CallableStatement cstmt = (CallableStatement)target;
        SQLXML result;
        if(_parameterName != null) {
            result = cstmt.getSQLXML(_parameterName);
        } else {
            result = cstmt.getSQLXML(_index);
        }
        return new SerialSQLXML(result);
    }

    public String toString() {
        return "CallableStatementGetSQLXMLCommand";
    }
    
	@Override
	public void write(Kryo kryo, Output output) {
		output.writeInt(_index);
		kryo.writeObjectOrNull(output, _parameterName, String.class);
	}

	@Override
	public void read(Kryo kryo, Input input) {
		_index = input.readInt();
		_parameterName = kryo.readObjectOrNull(input, String.class);
	}
}
