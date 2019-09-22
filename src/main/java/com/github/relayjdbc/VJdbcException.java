package com.github.relayjdbc;

public class VJdbcException extends Exception {
    static final long serialVersionUID = -7552211448253764663L;

    public VJdbcException() {
        super();
    }

    public VJdbcException(String msg) {
        super(msg);
    }

    public VJdbcException(String msg, Exception ex) {
        super(msg, ex);
    }
}
