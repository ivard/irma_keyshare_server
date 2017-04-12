package org.irmacard.keyshare.web;

import org.irmacard.keyshare.common.AuthorizationResult;
import org.irmacard.keyshare.common.IRMAHeaders;
import org.irmacard.keyshare.common.exceptions.KeyshareError;
import org.irmacard.keyshare.common.exceptions.KeyshareException;
import org.irmacard.keyshare.web.users.LogEntryType;
import org.irmacard.keyshare.web.users.User;
import org.irmacard.keyshare.web.users.Users;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.Arrays;

public class VerificationResource extends BaseVerifier {
	private static Logger logger = LoggerFactory.getLogger(VerificationResource.class);

	public static final int EXPIRY_NONLEEWAY = 120 * 1000; // 2 minutes (in ms)

	// TODO: maybe make this configurable?
	public static final String[] authOptions = {"pin"};

	@POST
	@Path("/isAuthorized")
	@Produces(MediaType.APPLICATION_JSON)
	public AuthorizationResult isAuthorized(@HeaderParam(IRMAHeaders.USERNAME) String username,
			@HeaderParam(IRMAHeaders.AUTHORIZATION) String jwt) {
		logger.info("Is authorized called for: {}", username);

		User u = Users.getValidUser(username);

		if(!u.isEnabled()) {
			u.addLog(LogEntryType.IRMA_APP_AUTH_REFUSED);
			throw new KeyshareException(KeyshareError.USER_BLOCKED, "" + u.getPinblockRelease());
		}
		if (!u.isEnrolled()) {
			throw new KeyshareException(KeyshareError.USER_NOT_REGISTERED);
		}

		if(isAuthorizedJWT(jwt, username, true)) {
			return new AuthorizationResult(AuthorizationResult.STATUS_AUTHORIZED, null);
		} else {
			return new AuthorizationResult(AuthorizationResult.STATUS_EXPIRED, Arrays.asList(authOptions));
		}
	}
}
