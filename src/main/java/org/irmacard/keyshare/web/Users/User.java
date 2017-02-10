package org.irmacard.keyshare.web.Users;

import de.henku.jpaillier.PublicKey;
import org.irmacard.api.common.exceptions.ApiError;
import org.irmacard.api.common.exceptions.ApiException;
import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.credentials.idemix.proofs.ProofP;
import org.irmacard.credentials.idemix.proofs.ProofPCommitmentMap;
import org.irmacard.credentials.idemix.proofs.ProofPListBuilder;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.KeyException;
import org.irmacard.credentials.info.PublicKeyIdentifier;
import org.irmacard.keyshare.common.UserLoginMessage;
import org.irmacard.keyshare.common.UserMessage;
import org.javalite.activejdbc.Model;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class User extends Model {
	private static Logger logger = LoggerFactory.getLogger(User.class);

	private static Map<Integer, ProofPListBuilder> builders = new HashMap<>();

	private static final int MAX_PIN_TRIES = 3;

	private transient ProofPListBuilder pbuilder = null;
	private transient PublicKey publicKey;

	public static final String USERNAME_FIELD = "username";
	public static final String PASSWORD_FIELD = "password";
	public static final String LAST_SEEN_FIELD = "lastSeen";
	public static final String PIN_FIELD = "pin";
	public static final String KEYSHARE_FIELD = "keyshare";
	public static final String PUBLICKEY_FIELD = "publickey";

	public static final String ENROLLED_FIELD = "enrolled";
	public static final String ENABLED_FIELD = "enabled";
	public static final String SESSION_FIELD = "sessionToken";
	public static final String PINCOUNTER_FIELD = "pincounter";

	public User(String username, String password, String pin, BigInteger secret, PublicKey publicKey) {
		setString(USERNAME_FIELD, username);
		setString(PASSWORD_FIELD, password);
		setString(PIN_FIELD, pin);
		setInteger(PINCOUNTER_FIELD, 0);
		setString(KEYSHARE_FIELD, secret.toString(16));

		setString(PUBLICKEY_FIELD, GsonUtil.getGson().toJson(publicKey));
		this.publicKey = publicKey;

		setBoolean(ENROLLED_FIELD, false);
		setBoolean(ENABLED_FIELD, true);
		saveIt();
	}

	public User(String username, String password, String pin, PublicKey publicKey) {
		this(username, password, pin, new BigInteger(255, new SecureRandom()), publicKey);
	}

	public User(UserLoginMessage user) {
		this(user.getUsername(), user.getPassword(), user.getPin(), user.getPublicKey());
	}

	public User() {}

	boolean verifyPassword(String password) {
		return getString(PASSWORD_FIELD).equals(password);
	}

	void setSessionToken(String sessionToken) {
		setSeen();
		setString(SESSION_FIELD, sessionToken);
	}

	public void setSeen() {
		setLong(LAST_SEEN_FIELD, System.currentTimeMillis()/1000);
	}

	public boolean isValidSession(String sessionid) {
		String sessiontoken = getSessionToken();

		boolean valid = sessiontoken != null
				&& sessiontoken.length() > 0
				&& sessiontoken.equals(sessionid);
		boolean notExpired = getLong(LAST_SEEN_FIELD) + 60*10 > System.currentTimeMillis()/1000;

		return valid && notExpired;
	}

	public String getUsername() {
		return getString(USERNAME_FIELD);
	}

	public int getID() {
		return getInteger("id");
	}

	public String getSessionToken() {
		return getString(SESSION_FIELD);
	}

	public boolean isEnrolled() {
		return getBoolean(ENROLLED_FIELD);
	}

	public void setEnrolled(boolean enrolled) {
		setBoolean(ENROLLED_FIELD, enrolled);
	}

	public PublicKey getPublicKey() {
		if (publicKey == null)
			publicKey = GsonUtil.getGson().fromJson(getString(PUBLICKEY_FIELD), PublicKey.class);

		return publicKey;
	}

	public UserMessage getAsMessage() {
		return new UserMessage(getUsername(), getSessionToken(), "" + getID(), isEnrolled(), isEnabled());
	}

	public String getPIN() {
		return getString(PIN_FIELD);
	}

	public int getPinCounter() {
		return getInteger(PINCOUNTER_FIELD);
	}

	public void setPinCounter(int count) {
		setInteger(PINCOUNTER_FIELD, count);
	}

	public boolean checkAndCountPin(String pin) {
		// TODO: use more elegant mechanism
		int pinCounter = getPinCounter();

		boolean correct = getPIN().equals(pin);
		pinCounter++;
		setPinCounter(pinCounter);

		if(correct) {
			addLog("Succesfully verified PIN!");
			resetPinCounter();
		} else {
			addLog("Pin verification failed (" + getPinTriesRemaining() + " tries remaining)");

			if(pinCounter >= MAX_PIN_TRIES) {
				logger.warn("Pin tried too often, disabled user {}", getUsername());
				addLog("Pin tried too often, user disabled");
				setEnabled(false);
			}
		}

		saveIt();
		return correct;
	}

	public int getPinTriesRemaining() {
		return MAX_PIN_TRIES - getPinCounter();
	}

	public BigInteger getKeyshare() {
		return new BigInteger(getString(KEYSHARE_FIELD), 16);
	}

	public ProofPCommitmentMap generateCommitments(List<PublicKeyIdentifier> pkids) throws InfoException, KeyException {
		pbuilder = new ProofPListBuilder(pkids, getKeyshare());
		pbuilder.generateRandomizers();
		builders.put(getID(), pbuilder);
		return pbuilder.calculateCommitments();
	}

	public ProofP buildProofP(BigInteger challenge) {
		pbuilder = builders.get(getID());
		if(pbuilder == null) {
			throw new ApiException(ApiError.UNEXPECTED_REQUEST);
		}

		ProofP proof = pbuilder.build(challenge, getPublicKey());

		// Ensure that we can only answer one challenge (lest we totally break security)
		pbuilder = null;
		addLog("Contributed to proof");

		return proof;
	}

	public void addLog(String message) {
		add(new LogEntryRecord(message));
	}

	public List<LogEntry> getLogs() {
		ArrayList<LogEntry> lst = new ArrayList<>();
		List<LogEntryRecord> records = getAll(LogEntryRecord.class)
				.orderBy(LogEntryRecord.DATE_FIELD + " desc");
		for(LogEntryRecord entry : records) {
			lst.add(new LogEntry(entry));
		}
		
		System.out.println("Log entries: ");
		for(LogEntry e : lst) {
			System.out.println(e);
		}
		return lst;
	}

	private void resetPinCounter() {
		setPinCounter(0);
	}

	public void setEnabled(boolean enabled) {
		if(enabled) {
			addLog("IRMA token enabled");
			resetPinCounter();
		} else {
			addLog("IRMA token disabled");
		}

		setBoolean(ENABLED_FIELD, enabled);
		saveIt();
	}

	public boolean isEnabled() {
		return getBoolean(ENABLED_FIELD);
	}
}
