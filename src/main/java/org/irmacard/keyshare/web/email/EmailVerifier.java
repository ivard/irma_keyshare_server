package org.irmacard.keyshare.web.email;

import org.irmacard.keyshare.web.KeyshareConfiguration;
import org.irmacard.keyshare.web.users.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.mail.internet.AddressException;
import java.util.List;

import static org.irmacard.keyshare.web.email.EmailVerificationRecord.DEFAULT_TIMEOUT;
import static org.irmacard.keyshare.web.email.EmailVerificationRecord.DEFAULT_VALIDITY;

public class EmailVerifier {
	private static Logger logger = LoggerFactory.getLogger(EmailVerifier.class);

	public static void verifyEmail(User u,
	                               String email,
	                               String subject,
	                               String body,
	                               String callback) throws AddressException {
		verifyEmail(u, email, subject, body, callback, DEFAULT_TIMEOUT, DEFAULT_VALIDITY);
	}

	public static void verifyEmail(User u,
	                               String email,
	                               String subject,
	                               String body,
	                               String callback,
	                               int timeout) throws AddressException {
		verifyEmail(u, email, subject, body, callback, timeout, DEFAULT_VALIDITY);
	}

	public static void verifyEmail(User u,
	                               String email,
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
		if (u != null) {
			record.setParent(u);
			record.saveIt();
		}
		String url = callback + record.getToken();
		if (body.contains("%s"))
			body = String.format(body, url);
		else
			body = body + "\n\n" + url;

		EmailSender.send(email, subject, body);
	}

	public static EmailVerificationRecord findRecord(String token) {
		// An email verification link should work only once,
		// so we check if time_verified has been set before.
		List<EmailVerificationRecord> list = EmailVerificationRecord.find(
				"token = ? AND time_verified IS NULL AND time_created + timeout > ?",
				token,
				System.currentTimeMillis() / 1000
		).include(User.class);
		if (list.size() == 0)
			return null;
		return list.get(0);
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
