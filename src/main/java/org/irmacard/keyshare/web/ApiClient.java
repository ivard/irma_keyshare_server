package org.irmacard.keyshare.web;

import io.jsonwebtoken.Jwts;
import org.irmacard.api.common.CredentialRequest;
import org.irmacard.api.common.issuing.IdentityProviderRequest;
import org.irmacard.api.common.issuing.IssuingRequest;
import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.info.CredentialIdentifier;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;

/**
 * Issuing client for the irma_api_server (mostly copied from irma_mno_server).
 */
public class ApiClient {
	public static String getIssuingJWT(HashMap<CredentialIdentifier, HashMap<String, String>> credentialList) {
		return Jwts.builder()
				.setPayload(getJwtClaims(credentialList))
				.signWith(KeyshareConfiguration.getInstance().getJwtAlgorithm(),
						KeyshareConfiguration.getInstance().getJwtPrivateKey())
				.compact();
	}

	/**
	 * Serialize the credentials to be issued to the body (claims) of a JWT token
	 */
	private static String getJwtClaims(HashMap<CredentialIdentifier, HashMap<String, String>> credentialList) {
		HashMap<String, Object> claims = new HashMap<>(4);
		claims.put("iprequest", getIdentityProviderRequest(credentialList));
		claims.put("iat", System.currentTimeMillis()/1000);
		claims.put("iss", KeyshareConfiguration.getInstance().getServerName());
		claims.put("sub", "issue_request");

		return GsonUtil.getGson().toJson(claims);
	}

	/**
	 * Convert the credentials to be issued to an {@link IdentityProviderRequest} for the API server
	 */
	private static IdentityProviderRequest getIdentityProviderRequest(HashMap<CredentialIdentifier, HashMap<String, String>> credentialList) {
		// Calculate expiry date: 6 months from now
		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.MONTH, 6);
		long validity = (calendar.getTimeInMillis() / Attributes.EXPIRY_FACTOR) * Attributes.EXPIRY_FACTOR / 1000;

		// Compute credential list for in the issuing request
		ArrayList<CredentialRequest> credentials = new ArrayList<>(credentialList.size());
		for (CredentialIdentifier identifier : credentialList.keySet())
			credentials.add(new CredentialRequest((int) validity, identifier, credentialList.get(identifier)));

		// Create issuing request, encode as unsigned JWT
		IssuingRequest request = new IssuingRequest(null, null, credentials);
		return new IdentityProviderRequest("", request, 120);
	}
}
