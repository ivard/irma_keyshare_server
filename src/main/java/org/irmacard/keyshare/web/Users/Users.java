package org.irmacard.keyshare.web.Users;

import org.irmacard.keyshare.common.UserLoginMessage;
import org.irmacard.keyshare.common.exceptions.KeyshareError;
import org.irmacard.keyshare.common.exceptions.KeyshareException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;

public class Users {
	private static Logger logger = LoggerFactory.getLogger(Users.class);

	static private SecureRandom srnd = new SecureRandom();

	static public User register(UserLoginMessage login) {
		logger.info("Registring user with username {}", login.getUsername());
		User u = getUser(login.getUsername());
		if(u != null) {
			// TODO: handle properly
			logger.info("Username {} already registered", login.getUsername());
			return null;
		}

		u = new User(login);
		System.out.println("Created user: " + u);
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
		logger.warn("Created session {} for user {}", sessionToken, u.toString());
		u.setSessionToken(sessionToken);
		u.saveIt();
		return new UserSession(u.getUsername(), sessionToken, u.getID());
	}

	static public User getUser(String username) {
		List<User> users = User.where(User.USERNAME_FIELD + " = ?", username);

		if(users.size() > 0) {
			return users.get(0);
		} else {
			return null;
		}
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
		System.out.println("Querying for user id = " + user_id);
		List<User> users = User.where("ID = ?", user_id);

		if(users.size() > 0) {
			return users.get(0);
		} else {
			return null;
		}
	}

    public static String randomSessionToken() {
        return new BigInteger(260, srnd).toString(32);
    }
}
