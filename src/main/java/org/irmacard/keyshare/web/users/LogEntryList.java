package org.irmacard.keyshare.web.users;

import java.util.List;

public class LogEntryList {
	private List<LogEntry> entries;
	private Long previous;
	private Long next;

	public LogEntryList(List<LogEntry> entries, Long previous, Long next) {
		this.entries = entries;
		this.previous = previous;
		this.next = next;
	}

	public List<LogEntry> getEntries() {
		return entries;
	}

	public long getPrevious() {
		return previous;
	}

	public long getNext() {
		return next;
	}
}
