package org.irmacard.keyshare.web;

import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.KeyException;
import org.irmacard.keyshare.common.IRMAHeaders;
import org.irmacard.keyshare.common.KeyshareResult;
import org.irmacard.keyshare.common.PinTokenMessage;
import org.irmacard.keyshare.common.RecoveryRequest;
import org.irmacard.keyshare.common.exceptions.KeyshareError;
import org.irmacard.keyshare.common.exceptions.KeyshareException;
import org.irmacard.keyshare.web.users.LogEntryType;
import org.irmacard.keyshare.web.users.User;
import org.irmacard.keyshare.web.users.Users;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import java.math.BigInteger;

public class RecoveryManager extends BaseVerifier {
    public static final String JWT_SUBJECT = "recovery_tok";
    private static Logger logger = LoggerFactory.getLogger(RecoveryManager.class);

    @Context
    private HttpServletRequest servletRequest;

    @Override
    protected String getJWTSubject() {
        return JWT_SUBJECT;
    }

    @POST
    @Path("/recovery/new-device")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public String initNewDevice(RecoveryRequest rr,
                                              @HeaderParam(IRMAHeaders.USERNAME) String username,
                                              @HeaderParam(IRMAHeaders.AUTHORIZATION) String jwt)
            throws InfoException, KeyException {

        logger.info("Recovery started for: " + username);
        User u = authorizeUser(jwt, username);
        u.applyDeltaOnKeyshare(new BigInteger(rr.getDelta()));
        return rr.getRedPacket().toString();
    }

    @POST
    @Path("/recovery/verify-pin")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public KeyshareResult pin(PinTokenMessage msg) {
        logger.info("Verifying PIN for user {}", msg.getID());

        KeyshareResult result;
        User u = Users.getValidUser(msg.getID());

        // DEBUG
        String jwt = getSignedJWT("user_id", msg.getID(), JWT_SUBJECT,
                KeyshareConfiguration.getInstance().getPinExpiry());
        return new KeyshareResult(KeyshareResult.STATUS_SUCCESS, jwt);
        // END DEBUG
/*
        if(!u.isEnabled()) {
            u.addLog(LogEntryType.PIN_CHECK_REFUSED);
            result = new KeyshareResult(KeyshareResult.STATUS_ERROR, "" + u.getPinblockRelease());
            return result;
        }
        if(!u.isEnrolled())
            throw new KeyshareException(KeyshareError.USER_NOT_REGISTERED);

        if(!u.checkAndCountRecoveryPin(msg.getPin())) {
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

        return result;*/
    }
}
