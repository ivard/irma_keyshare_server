package org.irmacard.keyshare.web;

import org.irmacard.api.common.exceptions.ApiError;
import org.irmacard.api.common.exceptions.ApiException;
import org.irmacard.keyshare.common.KeyshareResult;
import org.irmacard.keyshare.common.PinTokenMessage;
import org.irmacard.keyshare.web.Users.User;
import org.irmacard.keyshare.web.Users.Users;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

public class PinResource extends BaseVerifier {
	private static Logger logger = LoggerFactory.getLogger(PinResource.class);

	@POST
	@Path("/verify/pin")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public KeyshareResult pin(PinTokenMessage msg) {
		logger.info("Verifying PIN for user {}", msg.getID());

		User u = Users.getValidUser(msg.getID());
		if (!u.isEnabled() || !u.isEnrolled())
			throw new ApiException(ApiError.UNAUTHORIZED);

		KeyshareResult result;
		if(u.checkAndCountPin(msg.getPin())) {
			String jwt = getSignedJWT("user_id", msg.getID(), JWT_SUBJECT,
					KeyshareConfiguration.getInstance().getPinExpiry());
			result = new KeyshareResult(KeyshareResult.STATUS_SUCCESS, jwt);
		} else {
			result = new KeyshareResult(KeyshareResult.STATUS_ERROR, "" + u.getPinTriesRemaining());
		}

		return result;
	}
}
