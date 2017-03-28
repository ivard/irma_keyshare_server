package org.irmacard.keyshare.web;

import com.google.gson.reflect.TypeToken;
import org.irmacard.api.common.AttributeDisjunction;
import org.irmacard.api.common.AttributeDisjunctionList;
import org.irmacard.api.common.JwtParser;
import org.irmacard.api.common.disclosure.DisclosureProofResult;
import org.irmacard.api.common.ApiClient;
import org.irmacard.credentials.info.AttributeIdentifier;
import org.irmacard.credentials.info.CredentialIdentifier;
import org.irmacard.keyshare.common.UserLoginMessage;
import org.irmacard.keyshare.common.UserMessage;
import org.irmacard.keyshare.common.exceptions.KeyshareError;
import org.irmacard.keyshare.common.exceptions.KeyshareException;
import org.irmacard.keyshare.web.email.EmailVerifier;
import org.irmacard.keyshare.web.filters.RateLimit;
import org.irmacard.keyshare.web.users.User;
import org.irmacard.keyshare.web.users.Users;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.mail.internet.AddressException;
import javax.ws.rs.*;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import java.lang.reflect.Type;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

@Path("v1/web")
public class WebClientResource {
	private Logger logger = LoggerFactory.getLogger(this.getClass());

	@GET
	@Path("/users/{user_id}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response userInformation(@PathParam("user_id") int userID,
	                                @CookieParam("sessionid") String sessionid) {
		logger.info("Retrieving user " + userID);
		User u = Users.getLoggedInUser(userID, sessionid);

		if(u == null) {
			logger.warn("User {} couldn't be found!", userID);
			return null;
		}

		logger.trace("Requested user information for user {}", u.getUsername());
		return getCookiePostResponse(u);
	}

	// TODO Move this elsewhere? This is done by the app, not by the webclient
	@POST @Path("/users/selfenroll")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	@RateLimit
	public UserMessage userSelfEnroll(UserLoginMessage user) throws AddressException {
		User u = Users.register(user);
		if(u == null)
			throw new RuntimeException("User already exists?");

		EmailVerifier.verifyEmail(
				u.getUsername(),
				"Verify your email address",
				"To finish enrollment to the keyshare server, please click on the link below.",
				KeyshareConfiguration.getInstance().getUrl() + "/#enroll/"
		);

		return u.getAsMessage();
	}

	@GET
	@Path("/login-irma")
	@Produces(MediaType.TEXT_PLAIN)
	public String getEmailDisclosureJwt() {
		AttributeDisjunctionList list = new AttributeDisjunctionList(1);
		list.add(new AttributeDisjunction("E-mail address", getEmailAttributeIdentifier()));
		return ApiClient.getDisclosureJWT(list,
				KeyshareConfiguration.getInstance().getServerName(),
				KeyshareConfiguration.getInstance().getHumanReadableName(),
				KeyshareConfiguration.getInstance().getJwtAlgorithm(),
				KeyshareConfiguration.getInstance().getJwtPrivateKey()
				);
	}

	private AttributeIdentifier getEmailAttributeIdentifier() {
		KeyshareConfiguration conf = KeyshareConfiguration.getInstance();
		return new AttributeIdentifier(
				new CredentialIdentifier(
						conf.getSchemeManager(),
						conf.getEmailIssuer(),
						conf.getEmailCredential()),
				conf.getEmailAttribute()
		);
	}

	@POST
	@Path("/login-irma/proof")
	@RateLimit
	public Response loginUsingEmailAttribute(String jwt) {
		Type t = new TypeToken<Map<AttributeIdentifier, String>> () {}.getType();
		JwtParser<Map<AttributeIdentifier, String>> parser
				= new JwtParser<>(t, false, 10*1000, "disclosure_result", "attributes");
		parser.setSigningKey(KeyshareConfiguration.getInstance().getApiServerPublicKey());
		parser.parseJwt(jwt);

		Map<AttributeIdentifier, String> attrs = parser.getPayload();
		if (!DisclosureProofResult.Status.VALID.name().equals(parser.getClaims().get("status")))
			throw new KeyshareException(KeyshareError.MALFORMED_INPUT, "Invalid IRMA proof");

		return login(attrs.get(getEmailAttributeIdentifier()));
	}

	@GET
	@Path("/users/{user_id}/issue_email")
	@Produces(MediaType.TEXT_PLAIN)
	@RateLimit
	public String getEmailIssuanceJwt(@PathParam("user_id") int userID,
	                                  @CookieParam("sessionid") String sessionid) {
		User u = Users.getLoggedInUser(userID, sessionid);
		if(u == null)
			return null;

		HashMap<CredentialIdentifier, HashMap<String, String>> credentials = new HashMap<>();

		HashMap<String,String> attrs = new HashMap<>();
		attrs.put(KeyshareConfiguration.getInstance().getEmailAttribute(), u.getUsername());

		credentials.put(new CredentialIdentifier(
				KeyshareConfiguration.getInstance().getSchemeManager(),
				KeyshareConfiguration.getInstance().getEmailIssuer(),
				KeyshareConfiguration.getInstance().getEmailCredential()
		), attrs);

		return ApiClient.getIssuingJWT(credentials,
				KeyshareConfiguration.getInstance().getHumanReadableName(),
				true,
				KeyshareConfiguration.getInstance().getJwtAlgorithm(),
				KeyshareConfiguration.getInstance().getJwtPrivateKey()
		);
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

	@POST
	@Path("/users/{user_id}/delete")
	@Produces(MediaType.TEXT_PLAIN)
	public Response userDelete(@PathParam("user_id") int userID,
	                           @CookieParam("sessionid") String sessionid) {
		User u = Users.getLoggedInUser(userID, sessionid);
		if(u == null) {
			return null;
		}

		logger.warn("Unregistering user {}", u.getUsername());
		u.unregister();

		// Logout the user
		NewCookie nullCookie = new NewCookie("sessionid", null, "/", null, null, 0,
				KeyshareConfiguration.getInstance().isHttpsEnabled());
		return Response.ok("OK").cookie(nullCookie).build();
	}

	@GET
	@Path("/users/{user_id}/logs")
	@Produces(MediaType.APPLICATION_JSON)
	public Response getLogs(@PathParam("user_id") int userID,
	                        @CookieParam("sessionid") String sessionid) {
		return getLogs(userID, 0, sessionid);
	}

	@GET
	@Path("/users/{user_id}/logs/{time}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response getLogs(@PathParam("user_id") int userID,
	                        @PathParam("time") long time,
	                        @CookieParam("sessionid") String sessionid)  {
		User u = Users.getLoggedInUser(userID, sessionid);

		logger.debug("Requested logs for user {}", u.getUsername());

		if (time == 0)
			time = System.currentTimeMillis();

		return getCookiePostResponse(u.getLogs(time), u);
	}

	@GET
	@Path("/enroll/{token}")
	@RateLimit
	public Response enroll(@PathParam("token") String token) throws URISyntaxException {
		String email = EmailVerifier.getVerifiedAddress(token);
		if (email == null)
			return Response.status(Response.Status.NOT_FOUND).build();
		return login(email);
	}

	private Response login(String email) {
		User user = Users.getValidUser(email);
		user.setEnrolled(true);
		Users.getSessionForUser(user);

		return getCookiePostResponse(user);
	}

	@POST
	@Path("/login")
	@Consumes(MediaType.APPLICATION_JSON)
	@RateLimit
	public Response userLogin(UserLoginMessage user) throws AddressException {
		String email = user.getUsername();

		if (User.count(User.USERNAME_FIELD + " = ?", email) != 0) {
			logger.info("Sending OTP to {}", email);
			EmailVerifier.verifyEmail(
					email,
					"Log in on keyshare server",
					"Click on the link below to log in on the keyshare server.",
					KeyshareConfiguration.getInstance().getUrl() + "/#login/",
					60 * 60 // 1 hour
			);
		} else {
			logger.warn("Received login attempt for nonexisting user: {}");
		}

		// If we return nothing, null, the empty string, or a bare word
		// jQuery consider the request to have failed. Fine. Have an empty object
		return Response.accepted("{}").build();
	}

	@GET
	@Path("/login/{token}")
	@RateLimit
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
			new NewCookie("sessionid", u.getSessionToken(), "/", null, null,
					KeyshareConfiguration.getInstance().getSessionTimeout()*60,
					KeyshareConfiguration.getInstance().isHttpsEnabled()),
			new NewCookie("userid", Integer.toString(u.getID()), "/", null, null,
					KeyshareConfiguration.getInstance().getSessionTimeout()*60,
					KeyshareConfiguration.getInstance().isHttpsEnabled())
		};
	}
}
