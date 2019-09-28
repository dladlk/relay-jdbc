package com.github.relayjdbc;

import com.github.relayjdbc.command.DecoratedCommandSink;
import com.github.relayjdbc.serial.UIDEx;

/**
 * Base class for all virtual JDBC-Classes. All VJDBC-Objects have a unique id and a
 * reference to a command sink which can process commands generated by the VJDBC object.
 */
public abstract class VirtualBase {
    protected UIDEx _objectUid;
    protected DecoratedCommandSink _sink;

    protected VirtualBase(UIDEx objectuid, DecoratedCommandSink sink) {
        _objectUid = objectuid;
        _sink = sink;
    }

    public UIDEx getObjectUID() {
        return _objectUid;
    }
}
