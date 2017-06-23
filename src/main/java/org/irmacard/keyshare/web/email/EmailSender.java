package org.irmacard.keyshare.web.email;

import org.irmacard.keyshare.web.KeyshareConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.mail.*;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Properties;

public class EmailSender {
	private static Logger logger = LoggerFactory.getLogger(EmailSender.class);

	public static void send(String email, String subject, String body) throws AddressException {
		InternetAddress[] addresses = InternetAddress.parse(email);
		if (addresses.length != 1)
			throw new AddressException("Invalid amount of (comma-separated) addresses given (should be 1)");

		Properties props = new Properties();
		props.put("mail.smtp.starttls.required", "true");
		props.put("mail.smtp.port", KeyshareConfiguration.getInstance().getMailPort());
		props.put("mail.smtp.host", KeyshareConfiguration.getInstance().getMailHost());

		Session session = null;
		if (KeyshareConfiguration.getInstance().getMailUser().length() > 0) {
			props.put("mail.smtp.auth", "true");
			session = Session.getInstance(props, new Authenticator() {
				@Override
				protected PasswordAuthentication getPasswordAuthentication() {
					return new PasswordAuthentication(KeyshareConfiguration.getInstance().getMailUser(),
							KeyshareConfiguration.getInstance().getMailPassword());
				}
			});
		} else {
			session = Session.getInstance(props);
		}

		try {
			Message message = new MimeMessage(session);
			message.setFrom(new InternetAddress(KeyshareConfiguration.getInstance().getMailFrom()));
			message.setRecipients(Message.RecipientType.TO, addresses);
			message.setSubject(subject);
			message.setText(body);
			Transport.send(message);
			logger.info("Sent mail to {}", email);
		} catch (MessagingException e) {
			logger.error("Sending mail to {} failed:\n{}", email, e.getMessage());
		}
	}
}
