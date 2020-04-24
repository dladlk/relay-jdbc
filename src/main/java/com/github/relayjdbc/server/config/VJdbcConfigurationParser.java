package com.github.relayjdbc.server.config;

import java.io.InputStream;
import java.util.Properties;

import org.apache.commons.digester.Digester;
import org.apache.commons.digester.substitution.MultiVariableExpander;
import org.apache.commons.digester.substitution.VariableSubstitutor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

class VJdbcConfigurationParser {

    private static final Log _logger = LogFactory.getLog(VJdbcConfigurationParser.class);


    /**
     * Initialization with pre-opened InputStream.
     * @param configResourceInputStream InputStream
     * @throws ConfigurationException
     */
    public static VJdbcConfiguration parse(InputStream configResourceInputStream, Properties configVariables) throws ConfigurationException {
            try {
            	VJdbcConfiguration configuration = new VJdbcConfiguration();
                Digester digester = createDigester(configuration, configVariables);
                digester.parse(configResourceInputStream);
                configuration.validateConnections();;
                if(_logger.isInfoEnabled()) {
                	configuration.log();
                }
                return configuration;
            } catch(Exception e) {
                String msg = "relayjdbc-configuration failed";
                _logger.error(msg, e);
                throw new ConfigurationException(msg, e);
            }        
    }


    /**
     * Initialization with resource.
     * @param configResource Resource to be loaded by the ClassLoader
     * @throws ConfigurationException
     */
    public static VJdbcConfiguration parse(String configResource, Properties configVariables) throws ConfigurationException {

            try {
            	VJdbcConfiguration configuration = new VJdbcConfiguration();
                Digester digester = createDigester(configuration, configVariables);
                digester.parse(configResource);
                configuration.validateConnections();            	
                if(_logger.isInfoEnabled()) {
                	configuration.log();
                }
                return configuration;
            } catch(Exception e) {
                String msg = "relayjdbc-configuration failed";
                _logger.error(msg, e);
                throw new ConfigurationException(msg, e);
            }
    }    
    
	private static Digester createDigester(VJdbcConfiguration configuration, Properties vars) {
	    Digester digester = createDigester(configuration);
	
	    if(vars != null) {
	        MultiVariableExpander expander = new MultiVariableExpander();
	        expander.addSource("$", vars);
	        digester.setSubstitutor(new VariableSubstitutor(expander));
	    }
	
	    return digester;
	}
		
	
	private static Digester createDigester(VJdbcConfiguration configuration) {
	    Digester digester = new Digester();
	    
	    /*
	     * When running devtools Spring Boot app, without line below Digester loads class not with actual class loader so it fails with reading configuration.
	     * 
	     * TODO: DLK: Remove digester.setUseContextClassLoader(true) it in future, when configuration loading in Spring Boot is replaced with database configuration
	     */
	    digester.setUseContextClassLoader(true);
	
	    digester.push(configuration);
	
	    digester.addObjectCreate("relayjdbc-configuration/occt", DigesterOcctConfiguration.class);
	    digester.addSetProperties("relayjdbc-configuration/occt");
	    digester.addSetNext("relayjdbc-configuration/occt",
	            "setOcctConfiguration",
	            OcctConfiguration.class.getName());
	
	    digester.addObjectCreate("relayjdbc-configuration/rmi", DigesterRmiConfiguration.class);
	    digester.addSetProperties("relayjdbc-configuration/rmi");
	    digester.addSetNext("relayjdbc-configuration/rmi",
	            "setRmiConfiguration",
	            RmiConfiguration.class.getName());
	
	    digester.addObjectCreate("relayjdbc-configuration/connection", DigesterConnectionConfiguration.class);
	    digester.addSetProperties("relayjdbc-configuration/connection");
	    digester.addSetNext("relayjdbc-configuration/connection",
	            "addConnection",
	            ConnectionConfiguration.class.getName());
	
	    digester.addObjectCreate("relayjdbc-configuration/connection/connection-pool", ConnectionPoolConfiguration.class);
	    digester.addSetProperties("relayjdbc-configuration/connection/connection-pool");
	    digester.addSetNext("relayjdbc-configuration/connection/connection-pool",
	            "setConnectionPoolConfiguration",
	            ConnectionPoolConfiguration.class.getName());
	
	    // Named-Queries
	    digester.addObjectCreate("relayjdbc-configuration/connection/named-queries", NamedQueryConfiguration.class);
	    digester.addCallMethod("relayjdbc-configuration/connection/named-queries/entry", "addEntry", 2);
	    digester.addCallParam("relayjdbc-configuration/connection/named-queries/entry", 0, "id");
	    digester.addCallParam("relayjdbc-configuration/connection/named-queries/entry", 1);
	    digester.addSetNext("relayjdbc-configuration/connection/named-queries",
	            "setNamedQueries",
	            NamedQueryConfiguration.class.getName());
	
	    // Query-Filters
	    digester.addObjectCreate("relayjdbc-configuration/connection/query-filters", QueryFilterConfiguration.class);
	    digester.addCallMethod("relayjdbc-configuration/connection/query-filters/deny", "addDenyEntry", 2);
	    digester.addCallParam("relayjdbc-configuration/connection/query-filters/deny", 0);
	    digester.addCallParam("relayjdbc-configuration/connection/query-filters/deny", 1, "type");
	    digester.addCallMethod("relayjdbc-configuration/connection/query-filters/allow", "addAllowEntry", 2);
	    digester.addCallParam("relayjdbc-configuration/connection/query-filters/allow", 0);
	    digester.addCallParam("relayjdbc-configuration/connection/query-filters/allow", 1, "type");
	    digester.addSetNext("relayjdbc-configuration/connection/query-filters",
	            "setQueryFilters",
	            QueryFilterConfiguration.class.getName());
	
	    return digester;
	}


}
