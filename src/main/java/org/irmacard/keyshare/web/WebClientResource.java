package org.irmacard.keyshare.web;

import org.irmacard.keyshare.common.UserLoginMessage;
import org.irmacard.keyshare.common.UserMessage;
import org.irmacard.keyshare.web.Users.LogEntry;
import org.irmacard.keyshare.web.Users.User;
import org.irmacard.keyshare.web.Users.UserSession;
import org.irmacard.keyshare.web.Users.Users;
import org.irmacard.keyshare.web.email.EmailVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.mail.internet.AddressException;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

@Path("v1/web")
public class WebClientResource {
	private Logger logger = LoggerFactory.getLogger(this.getClass());

	@POST
	@Path("/users")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public UserSession userRegister(UserLoginMessage user) {
		System.out.println("Registring user: " + user);
		User u = Users.register(user);

		UserSession session = null;
		if(u != null) {
			// TODO: return proper 201 status code, see for example http://stackoverflow.com/questions/4687271/jax-rs-how-to-return-json-and-http-status-code-together
			session = Users.getSessionForUser(u);
		} else {
			throw new RuntimeException("User already exists?");
		}
		
		return session;
	}

	@GET
	@Path("/users/{user_id}")
	@Produces(MediaType.APPLICATION_JSON)
	public UserMessage userInformation(@PathParam("user_id") int userID) {
		// TODO: actually check if user is authorized
		System.out.println("Retrieving user " + userID);
		User u = Users.getUserForID(userID);

		if(u == null) {
			System.out.println("User couldn't be found!");
			return null;
		} else {
			logger.warn("User found: {}!!!", u.toString());
		}

		logger.trace("Requested user information for user {}", u.getUsername());

		//Base.close();
		return u.getAsMessage();
	}

	@POST @Path("/users/selfenroll")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public UserMessage userSelfEnroll(UserLoginMessage user) throws AddressException {
		return userEnroll(userRegister(user).getUserID());
	}


	@POST
	@Path("/users/{user_id}/enroll")
	@Produces(MediaType.APPLICATION_JSON)
	public UserMessage userEnroll(@PathParam("user_id") int userID) throws AddressException {
		// TODO: actually check that the user is authorized
		User u = Users.getUserForID(userID);
		if(u == null) {
			return null;
		}

		logger.info("Added user {}", u.getUsername());

		EmailVerifier.verifyEmail(
				u.getUsername(),
				"Verify your email address",
				"To finish enrollment to the keyshare server, please click on the link below.",
				"v1/web/users/finishenroll"
		);
		u.setEnrolled(false);
		u.saveIt();
		return u.getAsMessage();
	}

	@GET
	@Path("/users/finishenroll/{token}")
	public Response enroll(@PathParam("token") String token) throws URISyntaxException {
		String email = EmailVerifier.getVerifiedAddress(token);
		if (email == null)
			return Response.status(Response.Status.NOT_FOUND).build();

		User user = Users.getValidUser(email);
		user.setEnrolled(true);
		user.saveIt();

		return Response.seeOther(new URI(KeyshareConfiguration.getInstance().getEnrollDoneUrl())).build();
	}

	@POST
	@Path("/users/{user_id}/enable")
	@Produces(MediaType.APPLICATION_JSON)
	public UserMessage userEnable(@PathParam("user_id") int userID) {
		// TODO: actually check that the user is authorized
		User u = Users.getUserForID(userID);
		if(u == null) {
			return null;
		}

		logger.info("Enabled IRMA app for user {}", u.getUsername());

		u.setEnabled(true);
		u.saveIt();
		return u.getAsMessage();
	}

	@POST
	@Path("/users/{user_id}/disable")
	@Produces(MediaType.APPLICATION_JSON)
	public UserMessage userDisable(@PathParam("user_id") int userID) {
		// TODO: actually check that the user is authorized
		User u = Users.getUserForID(userID);
		if(u == null) {
			return null;
		}

		logger.info("Disabled IRMA app for user {}", u.getUsername());

		u.setEnabled(false);
		u.saveIt();
		return u.getAsMessage();
	}

	@GET
	@Path("/users/{user_id}/logs")
	@Produces(MediaType.APPLICATION_JSON)
	public List<LogEntry> getLogs(@PathParam("user_id") int userID) {
		// TODO: actually check that the user is authorized
		User u = Users.getUserForID(userID);
		if(u == null) {
			return null;
		}

		logger.debug("Requested logs for user {}", u.getUsername());

		return u.getLogs();
	}

	@POST
	@Path("/login")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public UserSession userLogin(UserLoginMessage user) {
		User u = Users.verify(user);

		if(u != null) {
			return Users.getSessionForUser(u);
		} else {
			// TODO: this exception should not be wrapped, but instead just returned
			throw new NotFoundException();
		}
	}
}
