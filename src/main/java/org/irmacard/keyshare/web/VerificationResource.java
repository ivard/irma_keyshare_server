package org.irmacard.keyshare.web;

import java.util.Arrays;
import org.irmacard.keyshare.common.AuthorizationResult;
import org.irmacard.keyshare.common.IRMAHeaders;
import org.irmacard.keyshare.web.Users.User;
import org.irmacard.keyshare.web.Users.Users;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;

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
			u.addLog("Authentication of IRMA token refused because of block");
			return new AuthorizationResult(AuthorizationResult.STATUS_BLOCKED, null);
		}

		if(isAuthorizedJWT(jwt, username, true)) {
			return new AuthorizationResult(AuthorizationResult.STATUS_AUTHORIZED, null);
		} else {
			return new AuthorizationResult(AuthorizationResult.STATUS_EXPIRED, Arrays.asList(authOptions));
		}
	}
}
