package org.irmacard.keyshare.web.users;

import org.javalite.activejdbc.Model;

public class LogEntryRecord extends Model {
	public static final String DATE_FIELD = "time";
	public static final String EVENT_FIELD = "event";
	public static final String PARAM_FIELD = "param";

	public LogEntryRecord(long time, LogEntryType event) {
		setLong(DATE_FIELD, time);
		setString(EVENT_FIELD, event);
		saveIt();
	}

	public LogEntryRecord(long time, LogEntryType event, int param) {
		setLong(DATE_FIELD, time);
		setString(EVENT_FIELD, event);
		setInteger(PARAM_FIELD, param);
		saveIt();
	}

	public LogEntryRecord(LogEntryType event) {
		this(System.currentTimeMillis() / 1000, event);
	}

	public LogEntryRecord(LogEntryType event, int param) {
		this(System.currentTimeMillis() / 1000, event, param);
	}

	public LogEntryRecord() {}

	public long getTime() {
		return getLong(DATE_FIELD);
	}

	public LogEntryType getEvent() {
		return LogEntryType.valueOf(getString(EVENT_FIELD));
	}

	public Integer getParam() {
		return getInteger(PARAM_FIELD);
	}
}
