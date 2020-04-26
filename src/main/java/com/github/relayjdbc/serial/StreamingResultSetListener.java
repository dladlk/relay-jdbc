package com.github.relayjdbc.serial;

import java.sql.ResultSet;
import java.sql.ResultSetMetaData;

public interface StreamingResultSetListener {

	void populate(ResultSet rs, ResultSetMetaData metaData, RowPacket page, StreamingResultSet streamingResultSet);

}
