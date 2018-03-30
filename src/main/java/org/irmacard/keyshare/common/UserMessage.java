package org.irmacard.keyshare.common;

import org.irmacard.keyshare.web.email.EmailAddress;

import java.util.ArrayList;
import java.util.List;

public class UserMessage {
		private String username;
		private String sessionToken;
		private String ID;
		private boolean enrolled;
		private boolean enabled;
		private boolean emailIssued;
		private List<String> emailAddresses;

		public UserMessage() {};

		public UserMessage(String username, String sessionToken, String ID, boolean enrolled, boolean enabled, boolean emailIssued, List<EmailAddress> emailAddresses) {
			this.username = username;
			this.sessionToken = sessionToken;
			this.ID = ID;
			this.enrolled = enrolled;
			this.emailIssued = emailIssued;
			this.setEnabled(enabled);

			this.emailAddresses = new ArrayList<>(emailAddresses.size());
			for (EmailAddress addr : emailAddresses) {
				this.emailAddresses.add(addr.get());
			}
		}

		public String getUsername() {
			return username;
		}

		public void setUsername(String username) {
			this.username = username;
		}

		public String getSessionToken() {
			return sessionToken;
		}

		public void setSessionToken(String sessionToken) {
			this.sessionToken = sessionToken;
		}

		public String getID() {
			return ID;
		}

		public void setID(String ID) {
			this.ID = ID;
		}

		public boolean isEnrolled() {
			return enrolled;
		}

		public void setEnrolled(boolean enrolled) {
			this.enrolled = enrolled;
		}

		public boolean isEnabled() {
			return enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public boolean isEmailIssued() {
			return emailIssued;
		}

		public void setEmailIssued(boolean emailIssued) {
			this.emailIssued = emailIssued;
		}

		public List<String> getEmailAddresses() {
			return emailAddresses;
		}
}
