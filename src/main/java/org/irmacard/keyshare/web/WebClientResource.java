package org.irmacard.keyshare.web;

import org.irmacard.keyshare.common.UserLoginMessage;
import org.irmacard.keyshare.common.UserMessage;
import org.irmacard.keyshare.web.Users.User;
import org.irmacard.keyshare.web.Users.Users;
import org.irmacard.keyshare.web.email.EmailVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.mail.internet.AddressException;
import javax.ws.rs.*;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import java.net.URISyntaxException;

@Path("v1/web")
public class WebClientResource {
	private Logger logger = LoggerFactory.getLogger(this.getClass());

	@GET
	@Path("/users/{user_id}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response userInformation(@PathParam("user_id") int userID,
	                                @CookieParam("sessionid") String sessionid) {
		System.out.println("Retrieving user " + userID);
		User u = Users.getLoggedInUser(userID, sessionid);

		if(u == null) {
			System.out.println("User couldn't be found!");
			return null;
		} else {
			logger.warn("User found: {}!!!", u.toString());
		}

		logger.trace("Requested user information for user {}", u.getUsername());
		return getCookiePostResponse(u);
	}

	// TODO Move this elsewhere? This is done by the app, not by the webclient
	@POST @Path("/users/selfenroll")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public UserMessage userSelfEnroll(UserLoginMessage user) throws AddressException {
		User u = Users.register(user);
		if(u == null)
			throw new RuntimeException("User already exists?");

		EmailVerifier.verifyEmail(
				u.getUsername(),
				"Verify your email address",
				"To finish enrollment to the keyshare server, please click on the link below.",
				KeyshareConfiguration.getInstance().getUrl() + "/#finishenroll/"
		);

		return u.getAsMessage();
	}

	@GET
	@Path("/finishenroll/{token}")
	public Response enroll(@PathParam("token") String token) throws URISyntaxException {
		String email = EmailVerifier.getVerifiedAddress(token);
		if (email == null)
			return Response.status(Response.Status.NOT_FOUND).build();

		User user = Users.getValidUser(email);
		user.setEnrolled(true);
		Users.getSessionForUser(user);

		return getCookiePostResponse(user);
	}

	@POST
	@Path("/users/{user_id}/enable")
	@Produces(MediaType.APPLICATION_JSON)
	public Response userEnable(@PathParam("user_id") int userID,
	                           @CookieParam("sessionid") String sessionid) {
		User u = Users.getLoggedInUser(userID, sessionid);
		if(u == null) {
			return null;
		}

		logger.info("Enabled IRMA app for user {}", u.getUsername());

		u.setEnabled(true);
		return getCookiePostResponse(u);
	}

	@POST
	@Path("/users/{user_id}/disable")
	@Produces(MediaType.APPLICATION_JSON)
	public Response userDisable(@PathParam("user_id") int userID,
	                            @CookieParam("sessionid") String sessionid) {
		User u = Users.getLoggedInUser(userID, sessionid);
		if(u == null) {
			return null;
		}

		logger.info("Disabled IRMA app for user {}", u.getUsername());

		u.setEnabled(false);
		return getCookiePostResponse(u);
	}

	@GET
	@Path("/users/{user_id}/logs")
	@Produces(MediaType.APPLICATION_JSON)
	public Response getLogs(@PathParam("user_id") int userID,
	                        @CookieParam("sessionid") String sessionid) {
		User u = Users.getLoggedInUser(userID, sessionid);

		logger.debug("Requested logs for user {}", u.getUsername());

		return getCookiePostResponse(u.getLogs(), u);
	}

	@POST
	@Path("/login")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response userLogin(UserLoginMessage user) throws AddressException {
		String email = user.getUsername();

		if (User.count(User.USERNAME_FIELD + " = ?", email) != 0) {
			EmailVerifier.verifyEmail(
					email,
					"Log in on keyshare server",
					"Click on the link below to log in on the keyshare server.",
					KeyshareConfiguration.getInstance().getUrl() + "/#login/",
					60 * 60 // 1 hour
			);
		}

		// If we return nothing, null, the empty string, or a bare word
		// jQuery consider the request to have failed. Fine. Have an empty object
		return Response.accepted("{}").build();
	}

	@GET
	@Path("/login/{token}")
	public Response oneTimePasswordLogin(@PathParam("token") String token) throws URISyntaxException {
		return enroll(token);
	}

	@GET
	@Path("/logout")
	@Produces(MediaType.TEXT_PLAIN)
	public Response logout(@CookieParam("sessionid") Cookie cookie) {
		if (cookie == null)
			return Response.ok("OK - No session").build();

		String sessionId = cookie.getValue();
		User u = User.findFirst(User.SESSION_FIELD + " = ?", sessionId);
		if (u == null)
			return Response.ok("OK - Unknown session").build();

		Users.clearSessionForUser(u);
		NewCookie nullCookie = new NewCookie("sessionid", null, "/", null, null, 0,
				KeyshareConfiguration.getInstance().isHttpsEnabled());
		return Response.ok("OK").cookie(nullCookie).build();
	}

	private Response getCookiePostResponse(User u) {
		return getCookiePostResponse(u.getAsMessage(), u);
	}

	private Response getCookiePostResponse(Object o, User u) {
		return Response
				.ok(o)
				.cookie(getSessionCookie(u))
				.build();
	}

	private NewCookie[] getSessionCookie(User u) {
		u.setSeen();
		u.saveIt();

		// TODO magic number alert
		return new NewCookie[] {
			new NewCookie("sessionid", u.getSessionToken(), "/", null, null, 60*60*10,
					KeyshareConfiguration.getInstance().isHttpsEnabled()),
			new NewCookie("userid", Integer.toString(u.getID()), "/", null, null, 60*60*10,
					KeyshareConfiguration.getInstance().isHttpsEnabled())
		};
	}
}
