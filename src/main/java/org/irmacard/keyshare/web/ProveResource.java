package org.irmacard.keyshare.web;

import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.credentials.idemix.proofs.ProofP;
import org.irmacard.credentials.idemix.proofs.ProofPCommitmentMap;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.KeyException;
import org.irmacard.credentials.info.PublicKeyIdentifier;
import org.irmacard.keyshare.common.IRMAHeaders;
import org.irmacard.keyshare.web.users.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.math.BigInteger;
import java.util.List;

@Path("prove")
public class ProveResource {
	public static final String JWT_SUBJECT = "ProofP";

	private static Logger logger = LoggerFactory.getLogger(ProveResource.class);
	private final VerificationResource verificationResource = new VerificationResource();

	@GET
	@Path("/publickey")
	@Produces(MediaType.APPLICATION_JSON)
	public String getPublickey() {
		return GsonUtil.getGson().toJson(KeyshareConfiguration.getInstance().getJwtPublicKey().getEncoded());
	}

	@POST
	@Path("/getCommitments")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public ProofPCommitmentMap getCommitments(List<PublicKeyIdentifier> pkids,
			@HeaderParam(IRMAHeaders.USERNAME) String username,
			@HeaderParam(IRMAHeaders.AUTHORIZATION) String jwt)
			throws InfoException, KeyException {

		User u = verificationResource.authorizeUser(jwt, username);

		logger.info("Answering proof request for: {}", username);

		return u.generateCommitments(pkids);
	}

	@POST
	@Path("/getResponse")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.TEXT_PLAIN)
	public String getResponse(BigInteger challenge,
			@HeaderParam(IRMAHeaders.USERNAME) String username,
			@HeaderParam(IRMAHeaders.AUTHORIZATION) String jwt) {

		User u = verificationResource.authorizeUser(jwt, username);

		logger.info("Gotten challenge for user: {}", username);

		ProofP proof = u.buildProofP(challenge);
		return verificationResource.getSignedJWT("ProofP", proof, JWT_SUBJECT);
	}
}
