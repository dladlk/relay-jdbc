package com.github.relayjdbc.command;

public abstract class AbstractCommand implements Command {

	@Override
	public String toString() {
		return this.getClass().getSimpleName();
	}
}
