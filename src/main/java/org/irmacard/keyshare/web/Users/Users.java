package org.irmacard.keyshare.web.users;

import org.irmacard.keyshare.common.UserLoginMessage;
import org.irmacard.keyshare.common.exceptions.KeyshareError;
import org.irmacard.keyshare.common.exceptions.KeyshareException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.validation.constraints.NotNull;
import java.math.BigInteger;
import java.security.SecureRandom;

public class Users {
	private static Logger logger = LoggerFactory.getLogger(Users.class);

	static private SecureRandom srnd = new SecureRandom();

	@NotNull
	static public User register(UserLoginMessage login) {
		logger.info("Registering user with username {}", login.getUsername());

		User u = getUser(login.getUsername());
		if(u != null && u.isEnrolled()) {
			logger.info("Username {} already registered", login.getUsername());
			throw new KeyshareException(KeyshareError.USERNAME_UNAVAILABLE);
		}

		u = new User(login);
		u.setEnrolled(false);
		u.saveIt();

		return u;
	}

	static public User verify(UserLoginMessage login) {
		User u = getUser(login.getUsername());
		if(u == null) {
			// TODO: handle properly
			logger.info("Cannot find username: {}", login.getUsername());
			return null;
		}

		if(!u.verifyPassword(login.getPassword())) {
			// TODO: handle properly
			logger.info("Password for user {} is incorrect", login.getUsername());
			return null;
		}

		return u;
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
