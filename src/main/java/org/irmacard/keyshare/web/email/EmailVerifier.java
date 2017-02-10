package org.irmacard.keyshare.web.email;

import org.irmacard.keyshare.web.KeyshareApplication;
import org.irmacard.keyshare.web.KeyshareConfiguration;
import org.javalite.activejdbc.Base;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.mail.*;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;

import static java.util.concurrent.TimeUnit.HOURS;

public class EmailVerifier {
	private static Logger logger = LoggerFactory.getLogger(EmailVerifier.class);

	private static ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

	public static void verifyEmail(String email, String subject, String body, String callback) throws AddressException {
		InternetAddress[] addresses = InternetAddress.parse(email);
		if (addresses.length != 1)
			throw new AddressException("Invalid amount of (comma-separated) addresses given (should be 1)");

		Properties props = new Properties();
		props.put("mail.smtp.auth", "true");
		props.put("mail.smtp.starttls.enable", "true");
		props.put("mail.smtp.port", "587");
		props.put("mail.smtp.host", KeyshareConfiguration.getInstance().getMailHost());

		Session session = Session.getInstance(props, new Authenticator() {
			@Override protected PasswordAuthentication getPasswordAuthentication() {
				return new PasswordAuthentication(KeyshareConfiguration.getInstance().getMailUser(),
						KeyshareConfiguration.getInstance().getMailPassword());
			}
		});

		if (!callback.startsWith("/")) callback = "/" + callback;
		if (!callback.endsWith("/")) callback += "/";
		EmailVerificationRecord record = new EmailVerificationRecord(email, 60 * 60 * 24 * 3);
		String url = KeyshareConfiguration.getInstance().getApiUrl() + callback + record.getToken();

		try {
			Message message = new MimeMessage(session);
			message.setFrom(new InternetAddress(KeyshareConfiguration.getInstance().getMailFrom()));
			message.setRecipients(Message.RecipientType.TO, addresses);
			message.setSubject(subject);
			message.setText(body + "\n\n" + url);
			Transport.send(message);
			logger.info("Sent mail to {}", email);
		} catch (MessagingException e) {
			logger.error("Sending mail to {} failed:\n{}", email, e.getMessage());
		}
	}

	public static String getVerifiedAddress(String token) {
		EmailVerificationRecord record = EmailVerificationRecord.findFirst("token = ?", token);
		if (record == null)
			return null;

		String email = record.getEmail();
		record.delete();
		return email;
	}

	public static void setupDatabaseCleanupTask() {
		final Runnable cleaner = new Runnable() {
			@Override public void run() {
				logger.warn("Deleting expired email verifications");
				KeyshareApplication.openDatabase();
				EmailVerificationRecord.delete("time_created + timeout < ?", System.currentTimeMillis()/1000);
			}
		};

		final ScheduledFuture<?> beeperHandle = scheduler.scheduleAtFixedRate(cleaner, 6, 6, HOURS);
	}
}
