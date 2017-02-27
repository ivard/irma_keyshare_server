package org.irmacard.keyshare.web.users;

import org.javalite.activejdbc.Model;

public class LogEntryRecord extends Model {
	public static final String DATE_FIELD = "time";
	public static final String EVENT_FIELD = "event";

	public LogEntryRecord(long time, String event) {
		setLong(DATE_FIELD, time);
		setString(EVENT_FIELD, event);
		saveIt();
	}

	public LogEntryRecord() {}

	public LogEntryRecord(String event) {
		this(System.currentTimeMillis() / 1000, event);
	}
	
	public long getTime() {
		return getLong(DATE_FIELD);
	}

	public String getEvent() {
		return getString(EVENT_FIELD);
	}
}
