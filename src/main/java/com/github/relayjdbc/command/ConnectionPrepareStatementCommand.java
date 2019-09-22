package com.github.relayjdbc.command;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.sql.Connection;
import java.sql.SQLException;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.KryoSerializable;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;

public class ConnectionPrepareStatementCommand implements Command, KryoSerializable {
    private static final long serialVersionUID = 3905239013827949875L;
    
    private static final int TYPE_ARG4 = 7;

	private static final int TYPE_ARG3 = 3;

	private static final int TYPE_ARG1 = 0;
	
    private String _sql;
    private int _type;
    private int _resultSetType;
    private int _resultSetConcurrency;
    private int _resultSetHoldability;

    public ConnectionPrepareStatementCommand() {
    }

    public ConnectionPrepareStatementCommand(String sql) {
        _sql = sql;
        _type = TYPE_ARG1;        
    }

    public ConnectionPrepareStatementCommand(String sql, int resultSetType, int resultSetConcurrency) {
        _sql = sql;
        _type = TYPE_ARG3;
        _resultSetType = resultSetType;
        _resultSetConcurrency = resultSetConcurrency;
    }

    public ConnectionPrepareStatementCommand(String sql, int resultSetType, int resultSetConcurrency, int resultSetHoldability) {
        _sql = sql;
        _type = TYPE_ARG4;
        _resultSetType = resultSetType;
        _resultSetConcurrency = resultSetConcurrency;
        _resultSetHoldability = resultSetHoldability;
    }

    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeObject(_sql);
        out.writeInt(_type);
        if ((_type & TYPE_ARG3)!=0) {
        	out.writeInt(_resultSetType);
        	out.writeInt(_resultSetConcurrency);
        	if (_type==TYPE_ARG4){
        		out.writeInt(_resultSetHoldability);
        	}
        }
    }

    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        _sql = (String) in.readObject();
        _type = in.readInt();
        if ((_type & TYPE_ARG3)!=0) {
        	_resultSetType = in.readInt();
        	_resultSetConcurrency = in.readInt();
        	if (_type==TYPE_ARG4){
        		_resultSetHoldability = in.readInt();
        	}
        }
    }

    public Object execute(Object target, ConnectionContext ctx) throws SQLException {
        // Resolve and check the query
        String sql = ctx.resolveOrCheckQuery(_sql);
        // Now choose the correct call
        switch(_type){
        case TYPE_ARG1:
        	return ((Connection) target).prepareStatement(sql);
        case TYPE_ARG3:
        	return ((Connection) target).prepareStatement(sql, _resultSetType, _resultSetConcurrency);
        case TYPE_ARG4:
        	return ((Connection) target).prepareStatement(sql, _resultSetType, _resultSetConcurrency, _resultSetHoldability);
        default: 
        	return ((Connection) target).prepareStatement(sql);
        }
    }

    public String toString() {
        return "ConnectionPrepareStatementCommand";
    }
    
	@Override
	public void write(Kryo kryo, Output output) {
		kryo.writeObjectOrNull(output, _sql, String.class);
		output.writeInt(_type);
        if ((_type & TYPE_ARG3)!=0) {
        	output.writeInt(_resultSetType);
        	output.writeInt(_resultSetConcurrency);
        	if (_type==TYPE_ARG4){
        		output.writeInt(_resultSetHoldability);
        	}
        }
	}

	@Override
	public void read(Kryo kryo, Input input) {
		_sql = kryo.readObjectOrNull(input, String.class);
		_type = input.readInt();
        if ((_type & TYPE_ARG3)!=0) {
        	_resultSetType = input.readInt();
        	_resultSetConcurrency = input.readInt();
        	if (_type==TYPE_ARG4){
        		_resultSetHoldability = input.readInt();
        	}
        }		
	}
}
