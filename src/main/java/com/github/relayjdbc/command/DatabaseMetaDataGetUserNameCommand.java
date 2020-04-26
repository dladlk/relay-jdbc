package com.github.relayjdbc.command;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;

import com.github.relayjdbc.RelayJdbcProperties;

public class DatabaseMetaDataGetUserNameCommand extends AbstractCommand {

	static final long serialVersionUID = 3543492350930057039L;;
	
	public static final DatabaseMetaDataGetUserNameCommand INSTANCE = new DatabaseMetaDataGetUserNameCommand();
	
	private DatabaseMetaDataGetUserNameCommand() {
		
	}
	
	public void writeExternal(ObjectOutput out) throws IOException {
	}

	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
	}

	public Object execute(Object target, ConnectionContext ctx) throws SQLException {
		Object userName = ctx.getClientInfo().get(RelayJdbcProperties.USER_NAME);
		if (userName==null || "".equals(userName)){
			userName = ((DatabaseMetaData)target).getUserName();
		}
		return userName;
	}
}
