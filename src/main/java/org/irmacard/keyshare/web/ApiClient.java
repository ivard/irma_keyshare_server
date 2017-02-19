package org.irmacard.keyshare.web;

import io.jsonwebtoken.Jwts;
import org.irmacard.api.common.AttributeDisjunctionList;
import org.irmacard.api.common.ClientRequest;
import org.irmacard.api.common.CredentialRequest;
import org.irmacard.api.common.disclosure.DisclosureProofRequest;
import org.irmacard.api.common.disclosure.ServiceProviderRequest;
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
		IdentityProviderRequest request = getIdentityProviderRequest(credentialList);

		return Jwts.builder()
				.setHeaderParam("kid", KeyshareConfiguration.getInstance().getServerName())
				.setPayload(getJwtClaims(request, "iprequest", "issue_request"))
				.signWith(KeyshareConfiguration.getInstance().getJwtAlgorithm(),
						KeyshareConfiguration.getInstance().getJwtPrivateKey())
				.compact();
	}

	public static String getDisclosureJWT(AttributeDisjunctionList list) {
		DisclosureProofRequest request = new DisclosureProofRequest(null, null, list);
		ServiceProviderRequest spRequest = new ServiceProviderRequest("", request, 120);

		return Jwts.builder()
				.setHeaderParam("kid", KeyshareConfiguration.getInstance().getServerName())
				.setPayload(getJwtClaims(spRequest, "sprequest", "verification_request"))
				.signWith(KeyshareConfiguration.getInstance().getJwtAlgorithm(),
						KeyshareConfiguration.getInstance().getJwtPrivateKey())
				.compact();
	}

	/**
	 * Serialize the credentials to be issued to the body (claims) of a JWT token
	 */
	private static String getJwtClaims(ClientRequest request,
	                                   String type,
	                                   String subject) {
		HashMap<String, Object> claims = new HashMap<>(4);
		claims.put(type, request);
		claims.put("iat", System.currentTimeMillis()/1000);
		claims.put("iss", KeyshareConfiguration.getInstance().getHumanReadableName());
		claims.put("sub", subject);

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
