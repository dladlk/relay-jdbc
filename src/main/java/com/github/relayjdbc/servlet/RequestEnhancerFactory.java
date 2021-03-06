package com.github.relayjdbc.servlet;

/**
 * Interface that must be implemented by the classes that register themselves with the
 * RelayJdbcProperties.SERVLET_REQUEST_ENHANCER_FACTORY.
 * @author Mike
 */
public interface RequestEnhancerFactory {
    /**
     * Factory method to create a RequestEnhancer object
     * @return Created RequestEnhancer
     */
    RequestEnhancer create();
}
