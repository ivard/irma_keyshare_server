package org.irmacard.keyshare.web.email;

import org.irmacard.keyshare.web.Users.Users;
import org.javalite.activejdbc.Model;

public class EmailVerificationRecord extends Model {
	private static final String EMAIL_FIELD = "email";
	private static final String TOKEN_FIELD = "token";
	private static final String TIMEOUT_FIELD = "timeout";
	private static final String TIME_CREATED_FIELD = "time_created";

	public EmailVerificationRecord() {}

	public EmailVerificationRecord(String email) {
		this(email, 60*60*24);
	}

	public EmailVerificationRecord(String email, long timeout) {
		setString(EMAIL_FIELD, email);
		setString(TOKEN_FIELD, Users.randomSessionToken());
		setLong(TIMEOUT_FIELD, timeout);
		setLong(TIME_CREATED_FIELD, System.currentTimeMillis()/1000);
		saveIt();
	}

	public String getEmail() {
		return getString(EMAIL_FIELD);
	}

	public String getToken() {
		return getString(TOKEN_FIELD);
	}
}
