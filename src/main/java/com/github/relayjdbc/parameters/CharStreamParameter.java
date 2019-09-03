// VJDBC - Virtual JDBC
// Written by Michael Link
// Website: http://vjdbc.sourceforge.net

package com.github.relayjdbc.parameters;

import java.io.*;
import java.sql.PreparedStatement;
import java.sql.SQLException;

import com.github.relayjdbc.serial.StreamSerializer;
import com.github.relayjdbc.util.SQLExceptionHelper;

public class CharStreamParameter implements PreparedStatementParameter {
    static final long serialVersionUID = -3934051486806729706L;

    private char[] _value;

    public CharStreamParameter() {
    }

    public CharStreamParameter(Reader x) throws SQLException {
        try {
            _value = StreamSerializer.toCharArray(x);
        } catch(IOException e) {
            throw SQLExceptionHelper.wrap(e);
        }
    }

    public CharStreamParameter(Reader x, long length) throws SQLException {
        try {
            _value = StreamSerializer.toCharArray(x, length);
        } catch(IOException e) {
            throw SQLExceptionHelper.wrap(e);
        }
    }
    
   CharStreamParameter(char[] value) {
		super();
		this._value = value;
	}

	public char[] getValue() {
        return _value;
    }

    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        _value = (char[])in.readObject();
    }

    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeObject(_value);
    }

    public void setParameter(PreparedStatement pstmt, int index) throws SQLException {
        pstmt.setCharacterStream(index, new CharArrayReader(_value), _value.length);
    }

    public String toString() {
        return "CharStream: " + _value.length + " chars";
    }
}