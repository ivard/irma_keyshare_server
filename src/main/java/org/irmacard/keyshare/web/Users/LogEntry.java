package org.irmacard.keyshare.web.users;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public class LogEntry {
	public String time;
	public String event;

	public LogEntry(LogEntryRecord record) {
		TimeZone tz = TimeZone.getTimeZone("UTC");
		DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm'Z'");
		df.setTimeZone(tz);
		
		df.format(new Date());

		this.time = df.format(new Date(record.getTime()));
		this.event = record.getEvent();
	}
	
	public String toString() {
		return "At " + time + ": " + event;
	}
}
