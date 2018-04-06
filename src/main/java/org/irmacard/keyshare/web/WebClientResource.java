package org.irmacard.keyshare.web;

import com.google.gson.reflect.TypeToken;
import foundation.privacybydesign.common.ApiClient;
import org.irmacard.api.common.*;
import org.irmacard.api.common.disclosure.DisclosureProofResult;
import org.irmacard.api.common.issuing.IdentityProviderRequest;
import org.irmacard.api.common.issuing.IssuingRequest;
import org.irmacard.credentials.info.AttributeIdentifier;
import org.irmacard.credentials.info.CredentialIdentifier;
import org.irmacard.keyshare.common.UserCandidate;
import org.irmacard.keyshare.common.UserLoginMessage;
import org.irmacard.keyshare.common.UserMessage;
import org.irmacard.keyshare.common.exceptions.KeyshareError;
import org.irmacard.keyshare.common.exceptions.KeyshareException;
import org.irmacard.keyshare.web.email.EmailAddress;
import org.irmacard.keyshare.web.email.EmailSender;
import org.irmacard.keyshare.web.email.EmailVerificationRecord;
import org.irmacard.keyshare.web.email.EmailVerifier;
import org.irmacard.keyshare.web.filters.RateLimit;
import org.irmacard.keyshare.web.users.User;
import org.irmacard.keyshare.web.users.Users;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.mail.internet.AddressException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.lang.reflect.Type;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

@Path("web")
public class WebClientResource {
	private Logger logger = LoggerFactory.getLogger(this.getClass());

	@Context
	private HttpServletRequest servletRequest;

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

	@GET @Path("/users/available/{username}")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	@RateLimit
	public boolean isUsernameAvailable(@PathParam("username") String username) {
		return true;
	}

	// TODO Move this elsewhere? This is done by the app, not by the webclient
	@POST @Path("/users/selfenroll")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	@RateLimit
	public UserMessage userSelfEnroll(UserLoginMessage user) throws AddressException {
		User u = Users.getUser(user.getUsername());
		KeyshareConfiguration conf = KeyshareConfiguration.getInstance();
		if (u == null || !u.isEnrolled()) {
			Historian.getInstance().recordRegistration(false, conf.getClientIp(servletRequest));
			u = Users.register(user);
			u.addEmailAddress(u.getUsername());
			EmailVerifier.verifyEmail(
					u,
					u.getUsername(),
					conf.getRegisterEmailSubject(),
					conf.getRegisterEmailBody(),
					conf.getUrl() + "/web/enroll/"
			);
		} else {
			Historian.getInstance().recordRegistration(true, conf.getClientIp(servletRequest));
			EmailSender.send(
					u.getUsername(),
					conf.getDoubleRegistrationEmailSubject(),
					conf.getDoubleRegistrationEmailBody()
			);
		}

		return new UserMessage();
	}

	@GET @Path("/users/auth-qr")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public ClientQr getAuthenticationQr() {
		return ApiClient.createApiSession(
				KeyshareConfiguration.getInstance().getApiServerUrl() + "irma_api_server/api/v2/verification/",
				getEmailDisclosureJwt()
		);
	}

	@GET
	@Path("/login-irma")
	@Produces(MediaType.TEXT_PLAIN)
	public String getEmailDisclosureJwt() {
		AttributeDisjunctionList list = new AttributeDisjunctionList(1);
		list.add(new AttributeDisjunction("E-mail address", getEmailAttributeIdentifier()));
		return ApiClient.getDisclosureJWT(
				list,
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
						conf.getEmailLoginCredential()),
				conf.getEmailLoginAttribute()
		);
	}

	// TODO move someplace else
	private Map<AttributeIdentifier, String> parseApiServerJwt(String jwt) {
		Type t = new TypeToken<Map<AttributeIdentifier, String>> () {}.getType();
		JwtParser<Map<AttributeIdentifier, String>> parser
				= new JwtParser<>(t, false, 10*1000, "disclosure_result", "attributes");
		parser.setSigningKey(KeyshareConfiguration.getInstance().getApiServerPublicKey());

		parser.parseJwt(jwt);

		if (!DisclosureProofResult.Status.VALID.name().equals(parser.getClaims().get("status"))) {
			return null;
		}

		return parser.getPayload();
	}

	@POST
	@Path("/login-irma/proof")
	@RateLimit
	public Response loginUsingEmailAttribute(String jwt) {
		KeyshareConfiguration conf = KeyshareConfiguration.getInstance();
		Map<AttributeIdentifier, String> attrs = parseApiServerJwt(jwt);
		if (attrs == null) {
			Historian.getInstance().recordLogin(false, false, conf.getClientIp(servletRequest));
			throw new KeyshareException(KeyshareError.MALFORMED_INPUT, "Invalid IRMA proof");
		}

		Historian.getInstance().recordLogin(true, false, conf.getClientIp(servletRequest));
		User user = Users.getValidUser(attrs.get(getEmailAttributeIdentifier()));
		loginUser(user);
		return getCookiePostResponse(user);
	}

	@GET
	@Path("/users/{user_id}/test_email")
	@Produces(MediaType.TEXT_PLAIN)
	@RateLimit
	public String getEmailTestJwt(@PathParam("user_id") int userID,
	                              @CookieParam("sessionid") String sessionid) {
		User u = Users.getLoggedInUser(userID, sessionid);
		if(u == null)
			return null;

		return getEmailDisclosureJwt();
	}

	@GET
	@Path("/users/{user_id}/add_email")
	@Produces(MediaType.TEXT_PLAIN)
	@RateLimit
	public String getAddEmailAddressJwt(@PathParam("user_id") int userID,
	                                    @CookieParam("sessionid") String sessionid) {
		User u = Users.getLoggedInUser(userID, sessionid);
		if (u == null) return null;
		return getEmailDisclosureJwt();
	}

	@POST
	@Path("/users/{user_id}/add_email")
	@Consumes(MediaType.TEXT_PLAIN)
	public Response addEmailAddress(@PathParam("user_id") int userID,
	                                @CookieParam("sessionid") String sessionid,
	                                String apiServerJwt) {
		User u = Users.getLoggedInUser(userID, sessionid);
		if (u == null) return null;

		Map<AttributeIdentifier, String> attrs = parseApiServerJwt(apiServerJwt);
		if (attrs == null) {
			throw new KeyshareException(KeyshareError.MALFORMED_INPUT, "Invalid IRMA proof");
		}

		u.addEmailAddress(attrs.get(getEmailAttributeIdentifier()));
		return getCookiePostResponse(u);
	}

	@POST
	@Path("/users/{user_id}/email_issued")
	public Response setEmailAddressIssued(@PathParam("user_id") int userID,
	                                      @CookieParam("sessionid") String sessionid) {
		User u = Users.getLoggedInUser(userID, sessionid);
		if(u == null)
			return null;
		u.setEmailAddressIssued();
		return getCookiePostResponse(u);
	}

	@GET
	@Path("/users/{user_id}/issue_email")
	@Produces(MediaType.TEXT_PLAIN)
	@RateLimit
	public String getEmailIssuanceJwt(@PathParam("user_id") int userID,
	                                  @CookieParam("sessionid") String sessionid) {
		User u = Users.getLoggedInUser(userID, sessionid);
		if(u == null || u.getEmailAddressIssued() || u.getEmailAddresses().size() == 0)
			// TODO some error message in case of the latter two conditions?
			return null;

		KeyshareConfiguration conf = KeyshareConfiguration.getInstance();
		ArrayList<CredentialRequest> credentials = new ArrayList<>(2);
		HashMap<String,String> attrs = new HashMap<>(1);

		attrs.put(conf.getEmailAttribute(), u.getEmailAddresses().get(0).get());
		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.YEAR, 1);
		credentials.add(new CredentialRequest(
				(int) CredentialRequest.floorValidityDate(calendar.getTimeInMillis(), true),
				new CredentialIdentifier(
						conf.getSchemeManager(),
						conf.getEmailIssuer(),
						conf.getEmailCredential()
				),
				attrs
		));

		IdentityProviderRequest ipRequest = new IdentityProviderRequest("", new IssuingRequest(null, null, credentials), 120);
		return ApiClient.getSignedIssuingJWT(ipRequest,
				conf.getServerName(),
				conf.getHumanReadableName(),
				conf.getJwtAlgorithm(),
				conf.getJwtPrivateKey()
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

		KeyshareConfiguration conf = KeyshareConfiguration.getInstance();
		Historian.getInstance().recordUnregistration(conf.getClientIp(servletRequest));
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
		KeyshareConfiguration conf = KeyshareConfiguration.getInstance();
		Historian.getInstance().recordEmailVerified(conf.getClientIp(servletRequest));

		// We are enrolling, so:
		// - the user was just created,
		// - as we are here the user clicked on a link sent to her email address,
		//   so she opted to provide her email address,
		// - this address was saved in the database when she enrolled as not yet verified,
		// - she may already have logged in on MyIRMA and associated other (verified) email addresses.
		// We need to lookup the email address she provided during enrollment, set it verified,
		// and log her in.

		EmailVerificationRecord record = EmailVerifier.findRecord(token);
		if (record == null) {
			Historian.getInstance().recordLogin(false, true, conf.getClientIp(servletRequest));
			return Response.status(Response.Status.NOT_FOUND).build();
		}

		// In case of enrollment, the email verification record should have a user_id parent
		// so that out of all users that have this email address, we know which one is now enrolling.
		User u = record.parent(User.class);
		if (u == null) {
			Historian.getInstance().recordLogin(false, true, conf.getClientIp(servletRequest));
			return Response.status(Response.Status.NOT_FOUND).build();
		}

		u.verifyEmailAddress(record.getEmail());
		loginUser(u);
		Historian.getInstance().recordLogin(true, true, conf.getClientIp(servletRequest));
		return Response
				.temporaryRedirect(new URI(KeyshareConfiguration.getInstance().getWebclientUrl()))
				.cookie(getSessionCookie(u, newCookie("enroll", "true")))
				.build();
	}

	@GET
	@Path("/candidates/{token}")
	public Response getCandidates(@PathParam("token") String token) throws URISyntaxException {
		KeyshareConfiguration conf = KeyshareConfiguration.getInstance();

		// Get email address verification record and all users that have this email address
		EmailVerificationRecord record = EmailVerifier.findRecord(token);
		if (record == null) {
			Historian.getInstance().recordLogin(false, true, conf.getClientIp(servletRequest));
			return Response.status(Response.Status.NOT_FOUND).build();
		}

		User u = null;
		List<EmailAddress> candidates = EmailAddress.find(record.getEmail());
		List<UserCandidate> users = new ArrayList<>(candidates.size());
		for (EmailAddress candidate : candidates) {
			u = candidate.parent(User.class);
			users.add(new UserCandidate(u.getUsername(), u.getLastSeen()));
		}
		return Response.ok(new UserMessage(users)).build(); // TODO this no longer needs to be a UserMessage
	}

	@GET
	@Path("/login/{token}")
	@RateLimit
	public Response oneTimePasswordLogin(@PathParam("token") String token) throws URISyntaxException {
		return oneTimePasswordLogin(token, null);
	}

	@GET
	@Path("/login/{token}/{username}")
	@Produces(MediaType.TEXT_PLAIN)
	@RateLimit
	public Response oneTimePasswordLogin(@PathParam("token") String token, @PathParam("username") String username) throws URISyntaxException {
		KeyshareConfiguration conf = KeyshareConfiguration.getInstance();

		// Get email address verification record and all users that have this email address
		EmailVerificationRecord record = EmailVerifier.findRecord(token);
		if (record == null) {
			Historian.getInstance().recordLogin(false, true, conf.getClientIp(servletRequest));
			return Response.status(Response.Status.NOT_FOUND).build();
		}
		List<EmailAddress> candidates = EmailAddress.find(record.getEmail());

		int size = candidates.size();
		User u = null; // The user to return if any

		// Multiple users have this email address, but no username was specified
		// Don't mark the token as consumed and put the token in a cookie for later retrieval of the candidates
		if (size > 1 && (username == null))
			return getMultipleCandidatesRedirectResponse(token);

		record.setVerified(); // This token is now consumed
		if (size > 1) { // a username was specified, look it up
			u = User.findFirst(User.USERNAME_FIELD + " = ?", username);
		}
		else if (size == 1) { // Only one user has this email address, just login the user immediately
			u = candidates.get(0).parent(User.class);
		}
		// else if (size == 0) nop;

		Historian.getInstance().recordLogin(u != null, true, conf.getClientIp(servletRequest));
		if (u == null)
			return Response.status(Response.Status.NOT_FOUND).build();

		loginUser(u);

		Response.ResponseBuilder builder = null;
		if (username == null)
			builder = Response.temporaryRedirect(new URI(KeyshareConfiguration.getInstance().getWebclientUrl()));
		else
			builder = Response.ok("OK");
		return builder.cookie(getSessionCookie(u, nullCookie("token"))).build();
	}

	private Response getMultipleCandidatesRedirectResponse(String token) throws URISyntaxException {
		return Response
				.temporaryRedirect(new URI(KeyshareConfiguration.getInstance().getWebclientUrl()))
				.cookie(newCookie("token", token))
				.build();
	}

	private void loginUser(User user) {
		user.setEnrolled(true);
		Users.getSessionForUser(user);
	}

	@POST
	@Path("/login")
	@Consumes(MediaType.APPLICATION_JSON)
	@RateLimit
	public Response userLogin(UserLoginMessage user) throws AddressException {
		String email = user.getEmail();

		if (EmailAddress.count(EmailAddress.EMAIL_ADDRESS_FIELD + " = ?", email) != 0) {
			KeyshareConfiguration conf = KeyshareConfiguration.getInstance();
			logger.info("Sending OTP to {}", email);
			EmailVerifier.verifyEmail(
					null,
					email,
					conf.getLoginEmailSubject(user.getLanguage()),
					conf.getLoginEmailBody(user.getLanguage()),
					conf.getUrl() + "/web/login/",
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
		return Response.ok("OK").cookie(nullCookie("sessionid")).build();
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

	private NewCookie newCookie(String key, String value) {
		return new NewCookie(key, value, "/", null, null,
				KeyshareConfiguration.getInstance().getSessionTimeout()*60,
				KeyshareConfiguration.getInstance().isHttpsEnabled());
	}

	private NewCookie nullCookie(String key) {
		return new NewCookie(key, null, "/", null, null, 0, KeyshareConfiguration.getInstance().isHttpsEnabled());
	}

	private NewCookie[] getSessionCookie(User u) {
		u.setSeen();
		u.saveIt();
		return new NewCookie[] {
				newCookie("sessionid", u.getSessionToken()),
				newCookie("userid", Integer.toString(u.getID()))
		};
	}

	private NewCookie[] getSessionCookie(User u, NewCookie cookie) {
		u.setSeen();
		u.saveIt();
		return new NewCookie[] {
				cookie,
				newCookie("sessionid", u.getSessionToken()),
				newCookie("userid", Integer.toString(u.getID()))
		};
	}
}
