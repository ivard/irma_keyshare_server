package org.irmacard.keyshare.web;

import io.jsonwebtoken.*;
import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.keyshare.common.exceptions.KeyshareError;
import org.irmacard.keyshare.common.exceptions.KeyshareException;
import org.irmacard.keyshare.web.users.User;
import org.irmacard.keyshare.web.users.Users;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.Path;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;

/**
 * Contains methods to deal with user's authentication tokens (which are just JWT's signed
 * by the keyshare server). It contains helpers to issue these JWT's and to verify them.
 *
 */
@Path("v1/users")
public class BaseVerifier {
	private static Logger logger = LoggerFactory.getLogger(BaseVerifier.class);

	public static final String JWT_SUBJECT = "auth_tok";
	public static final String JWT_ISSUER = KeyshareConfiguration.getInstance().getServerName();

	public static final int EXPIRY_NONLEEWAY = 120 * 1000; // 2 minutes (in ms)

	public static final String[] authOptions = {"pin"};

	protected static String getSignedJWT(String key, Object object, String subject, int expiry) {
		return Jwts.builder()
				.setPayload(getJwtClaims(key, object, subject, expiry))
				.signWith(KeyshareConfiguration.getInstance().getJwtAlgorithm(),
						KeyshareConfiguration.getInstance().getJwtPrivateKey())
				.compact();
	}

	/**
	 * Create the body of the JWT authentication token
	 */
	public static String getJwtClaims(String key, Object object, String subject, int expiry) {
		HashMap<String, Object> claims = new HashMap<>(4);
		claims.put(key, object);
		claims.put("iat", System.currentTimeMillis()/1000);
		claims.put("exp", System.currentTimeMillis()/1000 + expiry);
		claims.put("iss", JWT_ISSUER);
		claims.put("sub", subject);

		return GsonUtil.getGson().toJson(claims);
	}

	private static Claims parseJwt(String jwt) {
		Claims claims = null;
		try {
			claims = Jwts.parser()
					.requireSubject(JWT_SUBJECT)
					.requireIssuer(JWT_ISSUER)
					.setSigningKey(KeyshareConfiguration.getInstance().getJwtPublicKey())
					.parseClaimsJws(jwt)
					.getBody();
		} catch (UnsupportedJwtException|MalformedJwtException|SignatureException
				|ExpiredJwtException|IllegalArgumentException e) {
			logger.warn("JWT {} didn't verify", jwt);
			logger.warn(e.getMessage());
		}

		return claims;
	}

	/**
	 * When doing a preflight = true check, we artificially say that they
	 * JWT expires earlier.
	 */
	protected static boolean isAuthorizedJWT(String jwt, String username, boolean preflight) {
		Claims claims = parseJwt(jwt);
		if(claims == null) {
			return false;
		}

		// Take 2 minutes of extra expiry leeway
		long now = Calendar.getInstance().getTimeInMillis();
		long exp = claims.get("exp", Date.class).getTime();
		if(preflight && exp - now < 120 * 1000) {
			return false;
		}

		User u = Users.getUser(username);
		if(u == null) {
			logger.warn("Funny, we have a claim for a non-existing user {}", username);
			return false;
		}

		String user_id = claims.get("user_id", String.class);
		return user_id.equals(username);
	}

	public static boolean isAuthorizedJWT(String jwt, String username) {
		return isAuthorizedJWT(jwt, username, false);
	}

	public static User authorizeUser(String jwt, String username) {
		if(!isAuthorizedJWT(jwt, username)) {
			throw new KeyshareException(KeyshareError.UNAUTHORIZED);
		}

		User u = Users.getValidUser(username);
		if(u == null) {
			throw new KeyshareException(KeyshareError.USER_NOT_FOUND);
		}

		if(!u.isEnabled()) {
			throw new KeyshareException(KeyshareError.USER_BLOCKED, "Token disabled");
		}

		if (!u.isEnabled()) {
			throw new KeyshareException(KeyshareError.USER_NOT_REGISTERED);
		}

		return u;
	}
}
