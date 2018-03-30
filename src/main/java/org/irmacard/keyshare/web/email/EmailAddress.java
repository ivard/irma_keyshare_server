package org.irmacard.keyshare.web.email;

import org.javalite.activejdbc.Model;

public class EmailAddress extends Model {
	public static final String EMAIL_ADDRESS_FIELD = "emailAddress";
	public static final String VERIFIED_FIELD = "verified";

	// ActiveJDBC needs a default constructor
	public EmailAddress() {}

	public EmailAddress(String email) {
		setString(EMAIL_ADDRESS_FIELD, email);
		setBoolean(VERIFIED_FIELD, false);
		saveIt();
	}

	public void verify() {
		setBoolean(VERIFIED_FIELD, true);
		saveIt();
	}

	public String get() {
		return getString(EMAIL_ADDRESS_FIELD);
	}
}
