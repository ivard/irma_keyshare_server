package org.irmacard.keyshare.web.users;

import org.irmacard.keyshare.common.UserLoginMessage;
import org.irmacard.keyshare.common.exceptions.KeyshareError;
import org.irmacard.keyshare.common.exceptions.KeyshareException;
import org.irmacard.keyshare.web.email.EmailAddress;
import org.javalite.activejdbc.LazyList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.validation.constraints.NotNull;
import java.math.BigInteger;
import java.security.SecureRandom;

public class Users {
	private static Logger logger = LoggerFactory.getLogger(Users.class);

	static private SecureRandom srnd = new SecureRandom();

	@NotNull
	static public User register(@NotNull UserLoginMessage userData, boolean isEnrolled) {
		logger.info("Registering user with username {}", userData.getUsername());

		User u = getUser(userData.getUsername());
		if(u != null && u.isEnrolled()) {
			logger.info("Username {} already registered", userData.getUsername());
			return u;
		}

		u = new User(userData);
		u.setEnrolled(isEnrolled);
		u.saveIt();

		return u;
	}

	@NotNull
	static public User register(@NotNull UserLoginMessage login) {
		return register(login, false);
	}

	static public UserSession getSessionForUser(User u) {
		String sessionToken = randomSessionToken();
		logger.warn("Created session {} for user {}", sessionToken, u.getUsername());
		u.setSessionToken(sessionToken);
		u.saveIt();
		return new UserSession(u.getUsername(), sessionToken, u.getID());
	}

	static public void clearSessionForUser(User u) {
		logger.warn("Removing session {} for user {}", u.getSessionToken(), u.getUsername());
		u.setSessionToken("");
		u.saveIt();
	}

	static public User getUser(String username) {
		return User.findFirst(User.USERNAME_FIELD + " = ?", username);
	}

	public static User verifyEmailAddress(String email) {
		EmailAddress e = (EmailAddress) EmailAddress.find(EmailAddress.EMAIL_ADDRESS_FIELD + " = ?", email).include(User.class).get(0);
		if (e == null) return null;
		e.verify();
		return e.parent(User.class);
	}

	static public User getUserByEmail(String email) {
		// TODO: can one email address be associated to multiple users?
		LazyList<EmailAddress> users =  EmailAddress
				.find(EmailAddress.EMAIL_ADDRESS_FIELD + " = ? AND " + EmailAddress.VERIFIED_FIELD + " = TRUE", email)
				.include(User.class);

		if (users.size() == 0)
			return null;
		return users.get(0).parent(User.class);
	}

	static public User getLoggedInUser(int user_id, String sessionid) {
		User u = getUserForID(user_id);
		if (!u.isValidSession(sessionid)) {
			logger.info("User {} presented invalid sessionid cookie", u.getUsername());
			throw new KeyshareException(KeyshareError.USER_SESSION_INVALID);
		}
		return u;
	}

	/**
	 * Either returns the requested username, or throws a NOT_FOUND exception.
	 * @param username the requested username
	 * @return the requested user
	 */
	static public User getValidUser(String username) {
		User u = getUser(username);

		if(u == null) {
			logger.info("Trying to find user {} but it doesn't exist.", u);
			throw new KeyshareException(KeyshareError.USER_NOT_FOUND);
		}

		return u;
	}

	static public User getUserForID(int user_id) {
		logger.info("Querying for user id = " + user_id);
		return User.findFirst("ID = ?", user_id);
	}

	public static String randomSessionToken() {
		return new BigInteger(260, srnd).toString(32);
	}
}
