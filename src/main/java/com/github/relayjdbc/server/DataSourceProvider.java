package com.github.relayjdbc.server;

import javax.sql.DataSource;
import java.sql.SQLException;

/**
 * To use the DataSource-API with VJDBC a class must be provided
 * that implements the <code>DataSourceProvider</code> interface. 
 */
public interface DataSourceProvider {
    /**
     * Retrieves a DataSource object from the DataSourceProvider. This
     * will be used to create the JDBC connections.
     * @return DataSource to be used for creating the connections
     * @throws SQLException if retrieval of the DataSource fails
     */
    DataSource getDataSource() throws SQLException;
}
