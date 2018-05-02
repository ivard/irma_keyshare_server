package org.irmacard.keyshare.web;

import foundation.privacybydesign.common.ApiClient;
import org.bouncycastle.util.encoders.Base64;
import org.irmacard.api.common.ClientQr;
import org.irmacard.api.common.CredentialRequest;
import org.irmacard.api.common.exceptions.ApiException;
import org.irmacard.api.common.issuing.IdentityProviderRequest;
import org.irmacard.api.common.issuing.IssuingRequest;
import org.irmacard.credentials.info.CredentialIdentifier;
import org.irmacard.keyshare.common.UserLoginMessage;
import org.irmacard.keyshare.common.exceptions.KeyshareError;
import org.irmacard.keyshare.common.exceptions.KeyshareException;
import org.irmacard.keyshare.web.email.EmailVerifier;
import org.irmacard.keyshare.web.filters.RateLimit;
import org.irmacard.keyshare.web.users.User;
import org.irmacard.keyshare.web.users.Users;

import javax.mail.internet.AddressException;
import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;

@Path("client")
public class ClientResource {
	public static final int USERNAME_LENGTH = 8; // 64 bits, 12 characters

	@Context
	private HttpServletRequest servletRequest;

	private static SecureRandom rnd = new SecureRandom();

	@POST @Path("/register")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	@RateLimit
	public ClientQr userSelfEnroll(@NotNull UserLoginMessage userData) throws AddressException {
		KeyshareConfiguration conf = KeyshareConfiguration.getInstance();
		Historian.getInstance().recordRegistration(false, conf.getClientIp(servletRequest));

		String lang = userData.getLanguage();
		userData.setUsername(generateUsername());
		User u = Users.register(userData, true);

		String email = userData.getEmail();
		if (email != null && email.length() > 0) {
			if (conf.getCheckUserEnrolled())
				EmailVerifier.verifyEmail(
					u,
					userData.getEmail(),
					conf.getConfirmEmailSubject(lang),
					conf.getConfirmEmailBody(lang),
					conf.getUrl() + "/web/enroll/"
			);
		} else {
			u.setEmailAddressIssued();
		}

		// Construct request for login credential
		ArrayList<CredentialRequest> credentials = new ArrayList<>(2);
		HashMap<String, String> attrs = new HashMap<>(1);
		attrs.put(conf.getLoginAttribute(), u.getUsername());
		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.YEAR, 10); // TODO magic number
		credentials.add(new CredentialRequest(
				(int) CredentialRequest.floorValidityDate(calendar.getTimeInMillis(), true),
				new CredentialIdentifier( // TODO make new credential type for this
						conf.getSchemeManager(),
						conf.getIssuer(),
						conf.getLoginCredential()
				),
				attrs
		));
		IdentityProviderRequest ipRequest = new IdentityProviderRequest("", new IssuingRequest(null, null, credentials), 120);

		// Start the issuance session of the login credential at the API server
		String jwt = ApiClient.getSignedIssuingJWT(ipRequest,
				conf.getServerName(),
				conf.getHumanReadableName(),
				conf.getJwtAlgorithm(),
				conf.getJwtPrivateKey()
		);
		try {
			return ApiClient.createApiSession(
					KeyshareConfiguration.getInstance().getApiServerUrl() + "irma_api_server/api/v2/issue/",
					jwt
			);
		} catch (ApiException e) {
			throw e;
		} catch (Exception e) {
			throw new KeyshareException(KeyshareError.ISSUANCE_SESSION_FAILED, e.getMessage());
		}
	}

	private static String generateUsername() {
		byte[] bts = new byte[USERNAME_LENGTH];
		String name;
		do {
			// Generate username by Base64-ing randomness, excluding ugly characters
			// Would be more correct to use Base62
			rnd.nextBytes(bts);
			name = new String(Base64.encode(bts)).replace("/", "").replace("+", "").replace("=", "");
			// Check if candidate username already exists
		} while(User.count(User.USERNAME_FIELD + " = ?", name) != 0);
		return name;
	}
}
