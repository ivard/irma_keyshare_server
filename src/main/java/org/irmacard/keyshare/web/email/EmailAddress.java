package org.irmacard.keyshare.web.email;

import org.irmacard.keyshare.web.users.User;
import org.javalite.activejdbc.Model;

import java.util.List;

public class EmailAddress extends Model {
	public static final String EMAIL_ADDRESS_FIELD = "emailAddress";

	// ActiveJDBC needs a default constructor
	public EmailAddress() {}

	public EmailAddress(String email) {
		setString(EMAIL_ADDRESS_FIELD, email);
		saveIt();
	}

	public String get() {
		return getString(EMAIL_ADDRESS_FIELD);
	}

	public static List<EmailAddress> find(String email) {
		return EmailAddress
				.find(EmailAddress.EMAIL_ADDRESS_FIELD + " = ?", email)
				.include(User.class);
	}
}
