package org.irmacard.keyshare.web.users;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public class LogEntry {
	public String time;
	public String event;

	public static final DateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");

	static {
		DATE_FORMAT.setTimeZone(TimeZone.getTimeZone("UTC"));
	}

	public LogEntry(LogEntryRecord record) {
		this.time = DATE_FORMAT.format(new Date(record.getTime() * 1000));
		this.event = record.getEvent();
	}

	@Override
	public String toString() {
		return "At " + time + ": " + event;
	}
}
