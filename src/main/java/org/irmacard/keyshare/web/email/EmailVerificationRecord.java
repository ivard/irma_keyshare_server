package org.irmacard.keyshare.web.email;

import org.irmacard.keyshare.web.Users.Users;
import org.javalite.activejdbc.Model;

public class EmailVerificationRecord extends Model {
	private static final String EMAIL_FIELD = "email";
	private static final String TOKEN_FIELD = "token";
	private static final String TIMEOUT_FIELD = "timeout";
	private static final String VALIDITY_FIELD = "validity";
	private static final String TIME_CREATED_FIELD = "time_created";
	private static final String TIME_VERIFIED_FIELD = "time_verified";

	public EmailVerificationRecord() {}

	public EmailVerificationRecord(String email) {
		this(email, 60*60*24, 60*60*24);
	}

	public EmailVerificationRecord(String email, int timeout) {
		this(email, 60*60*24, 60*60*24);
	}

	public EmailVerificationRecord(String email, int timeout, int validity) {
		setString(EMAIL_FIELD, email);
		setString(TOKEN_FIELD, Users.randomSessionToken());
		setInteger(TIMEOUT_FIELD, timeout);
		setInteger(VALIDITY_FIELD, validity);
		setLong(TIME_CREATED_FIELD, System.currentTimeMillis()/1000);
		saveIt();
	}

	public String getEmail() {
		return getString(EMAIL_FIELD);
	}

	public String getToken() {
		return getString(TOKEN_FIELD);
	}

	public void setVerified() {
		setLong(TIME_VERIFIED_FIELD, System.currentTimeMillis()/1000);
		saveIt();
	}
}
