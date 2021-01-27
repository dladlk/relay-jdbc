package com.github.relayjdbc.server;

import static org.junit.Assert.*;

import org.junit.Test;

public class CommandDispatcherTest {

	@Test
	public void testAllowedMinorVersionDifference() {
		assertTrue(CommandDispatcher.allowedMinorVersionDifference(null, null));
		assertTrue(CommandDispatcher.allowedMinorVersionDifference("3.1.0k", "3.1.1k"));
		assertTrue(CommandDispatcher.allowedMinorVersionDifference("3.1.0k", "3.1.1k"));
		assertTrue(CommandDispatcher.allowedMinorVersionDifference("3.1.0k", "3.1.10k"));
		assertFalse(CommandDispatcher.allowedMinorVersionDifference("3.1.0k", "2.1.0k"));
		assertFalse(CommandDispatcher.allowedMinorVersionDifference("3.1.0k", "3.2.0k"));
		assertFalse(CommandDispatcher.allowedMinorVersionDifference("3.1.0k", "3.2."));
		assertFalse(CommandDispatcher.allowedMinorVersionDifference("3.1.0k", "3"));
		assertFalse(CommandDispatcher.allowedMinorVersionDifference("3.1.0k", "3.1k"));
	}

}
