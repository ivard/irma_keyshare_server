package org.irmacard.keyshare.web;

import com.google.gson.Gson;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.codehaus.jackson.map.util.JSONPObject;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.KeyException;
import org.irmacard.keyshare.common.*;
import org.irmacard.keyshare.common.exceptions.KeyshareError;
import org.irmacard.keyshare.common.exceptions.KeyshareException;
import org.irmacard.keyshare.web.users.LogEntryType;
import org.irmacard.keyshare.web.users.User;
import org.irmacard.keyshare.web.users.Users;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class RecoveryManager extends BaseVerifier {
    public static final String JWT_SUBJECT = "recovery_tok";
    private boolean useDefaultAuth = false; // Change to true if normal PIN should be used instead of recovery PIN
    private static Logger logger = LoggerFactory.getLogger(RecoveryManager.class);

    @Context
    private HttpServletRequest servletRequest;

    @Override
    protected String getJWTSubject() {
        if(useDefaultAuth) {
            return BaseVerifier.JWT_SUBJECT;
        }
        return JWT_SUBJECT;
    }

    @POST
    @Path("/recovery/setup")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public KeyshareResult setupRecovery (RecoveryPinInit hashedRecoveryPin,
                                 @HeaderParam(IRMAHeaders.USERNAME) String username,
                                 @HeaderParam(IRMAHeaders.AUTHORIZATION) String jwt)
            throws KeyshareException {
        logger.info("Setting up recovery for: " + username);

        useDefaultAuth = true; // Recovery PIN has not been set up yet, use normal PIN
        User u = authorizeUser(jwt, username);
        useDefaultAuth = false;
        u.setRecoveryPIN(hashedRecoveryPin.getHashedPin());

        return new KeyshareResult(KeyshareResult.STATUS_SUCCESS, "Recovery PIN initialized");
    }

    @POST
    @Path("/recovery/new-device")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public RecoveryServerKeyResponse initNewDevice(RecoveryRequest rr,
                                              @HeaderParam(IRMAHeaders.USERNAME) String username,
                                              @HeaderParam(IRMAHeaders.AUTHORIZATION) String jwt)
            throws InfoException, KeyException {

        logger.info("Recovery started for: " + username);
        User u = authorizeUser(jwt, username);

        u.setDeviceKey(new BigInteger(rr.getDelta()));
        KeyPair pair = loadServerRecoveryPair();
        RedPacket rp = null;
        try {
            byte[] decrypted = decrypt(pair.getPrivate(), rr.getRedPacket());
            Gson g = new Gson();
            rp = g.fromJson(new String(decrypted), RedPacket.class);
        } catch (Exception e) {
            e.printStackTrace();
            throw new KeyshareException(KeyshareError.MALFORMED_INPUT);
        }
        if(! rp.getUsername().equals(username)) {
            logger.warn(String.format("User %s tried to recover with wrong backup", username));
            throw new KeyshareException(KeyshareError.PROVIDED_BACKUP_WRONG);
        }
        return new RecoveryServerKeyResponse(rp.getServerKey());
    }

    @POST
    @Path("/recovery/verify-recovery-pin")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public KeyshareResult recoveryPin(PinTokenMessage msg) {
        logger.info("Verifying Recovery PIN for user {}", msg.getID());
        User u = Users.getValidUser(msg.getID());
        return checkPin(msg, u.getRecoveryPIN(), u);
    }

    @POST
    @Path("/recovery/verify-pin")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public KeyshareResult pin(PinTokenMessage msg) {
        logger.info("Verifying PIN for user {}", msg.getID());
        User u = Users.getValidUser(msg.getID());
        useDefaultAuth = true;
        KeyshareResult result = checkPin(msg, u.getPIN(), u);
        useDefaultAuth = false;
        return result;
    }

    private KeyshareResult checkPin(PinTokenMessage msg, String pin, User u) {
        KeyshareResult result;

        if(!u.isEnabled()) {
            u.addLog(LogEntryType.PIN_CHECK_REFUSED);
            result = new KeyshareResult(KeyshareResult.STATUS_ERROR, "" + u.getPinblockRelease());
            return result;
        }
        if(!u.isEnrolled())
            throw new KeyshareException(KeyshareError.USER_NOT_REGISTERED);

        if(!u.checkAndCountPin(msg.getPin(), pin)) {
            if (!u.isPinBlocked()) {
                result = new KeyshareResult(KeyshareResult.STATUS_FAILURE, "" + u.getPinTriesRemaining());
            } else {
                Historian.getInstance().recordPinBlocked(KeyshareConfiguration.getInstance().getClientIp(servletRequest));
                result = new KeyshareResult(KeyshareResult.STATUS_ERROR, "" + u.getPinblockRelease());
            }
        } else {
            String jwt = getSignedJWT("user_id", msg.getID(), getJWTSubject(),
                    KeyshareConfiguration.getInstance().getPinExpiry());
            result = new KeyshareResult(KeyshareResult.STATUS_SUCCESS, jwt);
        }

        return result;
    }

    public static byte[] decrypt(PrivateKey privateKey, byte [] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(encrypted);
    }

    private static final String KEYSHARE_SERVER_NAME = "pbdf";

    private KeyPair loadServerRecoveryPair() {
        /*
        X9ECParameters ecP = CustomNamedCurves.getByName("curve25519");
        ECParameterSpec ecSpec = EC5Util.convertToSpec(ecP);
        System.out.println("-------------------------------------------------");
        System.out.println(ecSpec.getGenerator().getAffineX());
        System.out.println(ecP.getG());
        System.out.println(ecP.getBaseEntry().getPoint().getAffineYCoord());
        KeyPairGenerator g = null;
        try {
            g = KeyPairGenerator.getInstance("ECDH", "BC");
            g.initialize(ecSpec, new SecureRandom());
        } catch (NoSuchAlgorithmException|NoSuchProviderException|InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return g.generateKeyPair();*/

        try {
            File privateKeyFile = new File("src/main/resources/irma_configuration/" + KEYSHARE_SERVER_NAME + "/recovery_private_key.der");
            byte[] keyBytes = new byte[(int) privateKeyFile.length()];
            FileInputStream fis = new FileInputStream(privateKeyFile);
            fis.read(keyBytes);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privKey = keyFactory.generatePrivate(spec);

            File publicKeyFile = new File("src/main/resources/irma_configuration/" + KEYSHARE_SERVER_NAME + "/recovery_public_key.der");
            keyBytes = new byte[(int) publicKeyFile.length()];
            fis = new FileInputStream(publicKeyFile);
            fis.read(keyBytes);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = factory.generatePublic(publicKeySpec);
            return new KeyPair(pubKey, privKey);
        } catch (IOException|NoSuchAlgorithmException|InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }
}
