package org.irmacard.keyshare.web;

import org.irmacard.keyshare.common.KeyshareResult;
import org.irmacard.keyshare.common.PinTokenMessage;
import org.irmacard.keyshare.common.ChangePinTokenMessage;
import org.irmacard.keyshare.common.exceptions.KeyshareError;
import org.irmacard.keyshare.common.exceptions.KeyshareException;
import org.irmacard.keyshare.web.users.LogEntryType;
import org.irmacard.keyshare.web.users.User;
import org.irmacard.keyshare.web.users.Users;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Context;
import javax.servlet.http.HttpServletRequest;

public class PinResource extends BaseVerifier {
	private static Logger logger = LoggerFactory.getLogger(PinResource.class);

	@Context
	private HttpServletRequest servletRequest;

	@POST
	@Path("/verify/pin")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public KeyshareResult pin(PinTokenMessage msg) {
		logger.info("Verifying PIN for user {}", msg.getID());

		KeyshareResult result;
		User u = Users.getValidUser(msg.getID());

		if(!u.isEnabled()) {
			u.addLog(LogEntryType.PIN_CHECK_REFUSED);
			result = new KeyshareResult(KeyshareResult.STATUS_ERROR, "" + u.getPinblockRelease());
			return result;
		}
		if(!u.isEnrolled())
			throw new KeyshareException(KeyshareError.USER_NOT_REGISTERED);

		if(!u.checkAndCountPin(msg.getPin())) {
			if (!u.isPinBlocked()) {
				result = new KeyshareResult(KeyshareResult.STATUS_FAILURE, "" + u.getPinTriesRemaining());
			} else {
				Historian.getInstance().recordPinBlocked(KeyshareConfiguration.getInstance().getClientIp(servletRequest));
				result = new KeyshareResult(KeyshareResult.STATUS_ERROR, "" + u.getPinblockRelease());
			}
		} else {
			String jwt = getSignedJWT("user_id", msg.getID(), JWT_SUBJECT,
					KeyshareConfiguration.getInstance().getPinExpiry());
			result = new KeyshareResult(KeyshareResult.STATUS_SUCCESS, jwt);
		}

		return result;
	}

	@POST
	@Path("/change/pin")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public KeyshareResult pinchange(ChangePinTokenMessage msg) {
		logger.info("Changing PIN for user {}", msg.getID());

		KeyshareResult result;
		User u = Users.getValidUser(msg.getID());

		if (!u.isEnabled()) {
			u.addLog(LogEntryType.PIN_CHECK_REFUSED);
			result = new KeyshareResult(KeyshareResult.STATUS_ERROR, "" + u.getPinblockRelease());
			return result;
		}
		if (!u.isEnrolled())
			throw new KeyshareException(KeyshareError.USER_NOT_REGISTERED);

		if (!u.checkAndCountPin(msg.getOldPin())) {
			if (!u.isPinBlocked()) {
				result = new KeyshareResult(KeyshareResult.STATUS_FAILURE, "" + u.getPinTriesRemaining());
			} else {
				Historian.getInstance().recordPinBlocked(KeyshareConfiguration.getInstance().getClientIp(servletRequest));
				result = new KeyshareResult(KeyshareResult.STATUS_ERROR, "" + u.getPinblockRelease());
			}
		} else {
			u.setPIN(msg.getNewPin());
			result = new KeyshareResult(KeyshareResult.STATUS_SUCCESS, "");
		}

		return result;
	}
}
