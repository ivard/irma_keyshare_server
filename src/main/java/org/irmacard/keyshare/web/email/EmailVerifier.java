package org.irmacard.keyshare.web.email;

import org.irmacard.keyshare.web.KeyshareConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.mail.internet.AddressException;

import static org.irmacard.keyshare.web.email.EmailVerificationRecord.DEFAULT_TIMEOUT;
import static org.irmacard.keyshare.web.email.EmailVerificationRecord.DEFAULT_VALIDITY;

public class EmailVerifier {
	private static Logger logger = LoggerFactory.getLogger(EmailVerifier.class);

	public static void verifyEmail(String email,
	                               String subject,
	                               String body,
	                               String callback) throws AddressException {
		verifyEmail(email, subject, body, callback, DEFAULT_TIMEOUT, DEFAULT_VALIDITY);
	}

	public static void verifyEmail(String email,
	                               String subject,
	                               String body,
	                               String callback,
	                               int timeout) throws AddressException {
		verifyEmail(email, subject, body, callback, timeout, DEFAULT_VALIDITY);
	}

	public static void verifyEmail(String email,
	                               String subject,
	                               String body,
	                               String callback,
	                               int timeout,
	                               int validity) throws AddressException {
		// If the callback is relative, prepend our url to it
		if (!callback.startsWith("http://") && !callback.startsWith("https://")) {
			if (!callback.startsWith("/")) callback = "/" + callback;
			if (!callback.endsWith("/")) callback += "/";
			callback = KeyshareConfiguration.getInstance().getWebclientUrl() + callback;
		}

		EmailVerificationRecord record = new EmailVerificationRecord(email, timeout, validity);
		String url = callback + record.getToken();
		if (body.contains("%s"))
			body = String.format(body, url);
		else
			body = body + "\n\n" + url;

		EmailSender.send(email, subject, body);
	}

	public static String getVerifiedAddress(String token) {
		// An email verification link should work only once,
		// so we check if time_verified has been set before.
		EmailVerificationRecord record = EmailVerificationRecord.findFirst(
				"token = ? AND time_verified IS NULL AND time_created + timeout > ?",
				token,
				System.currentTimeMillis() / 1000
		);
		if (record == null)
			return null;

		record.setVerified();
		return record.getEmail();
	}

	public static boolean isAddressVerified(String email) {
		return EmailVerificationRecord.count(
				"email = ? " +
						"AND time_verified IS NOT NULL " +
						"AND time_verified + validity > ?",
				email, System.currentTimeMillis()/1000
		) > 0;
	}
}
