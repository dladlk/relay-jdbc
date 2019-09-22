package com.github.relayjdbc.parameters;

import com.github.relayjdbc.serial.SerialRef;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.sql.PreparedStatement;
import java.sql.Ref;
import java.sql.SQLException;

public class RefParameter implements PreparedStatementParameter {
    static final long serialVersionUID = 8647675527971168478L;

    private SerialRef _value;

    public RefParameter() {
    }
    
    public RefParameter(Ref value) throws SQLException {
        _value = new SerialRef(value);
    }
    
    public RefParameter(SerialRef value) {
		this._value = value;
	}

	public SerialRef getValue() {
		return _value;
	}



	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        _value = (SerialRef)in.readObject();
    }

    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeObject(_value);
    }

    public void setParameter(PreparedStatement pstmt, int index) throws SQLException {
        pstmt.setRef(index, _value);
    }

    public String toString() {
        return "Ref: " + _value;
    }
}
