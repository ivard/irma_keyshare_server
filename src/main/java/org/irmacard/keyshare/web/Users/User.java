package org.irmacard.keyshare.web.users;

import de.henku.jpaillier.PublicKey;
import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.credentials.idemix.proofs.ProofP;
import org.irmacard.credentials.idemix.proofs.ProofPCommitmentMap;
import org.irmacard.credentials.idemix.proofs.ProofPListBuilder;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.KeyException;
import org.irmacard.credentials.info.PublicKeyIdentifier;
import org.irmacard.keyshare.common.UserLoginMessage;
import org.irmacard.keyshare.common.UserMessage;
import org.irmacard.keyshare.common.exceptions.KeyshareError;
import org.irmacard.keyshare.common.exceptions.KeyshareException;
import org.irmacard.keyshare.web.KeyshareConfiguration;
import org.irmacard.keyshare.web.email.EmailAddress;
import org.javalite.activejdbc.Model;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class User extends Model {
	private static Logger logger = LoggerFactory.getLogger(User.class);

	private static Map<Integer, ProofPListBuilder> builders = new HashMap<>();

	private static final int MAX_PIN_TRIES = 3;
	private static final int BACKOFF_FACTOR = 2;
	private static final int BACKOFF_START = 1;

	private transient ProofPListBuilder pbuilder = null;
	private transient PublicKey publicKey;

	public static final String USERNAME_FIELD = "username";
	public static final String PASSWORD_FIELD = "password";
	public static final String LAST_SEEN_FIELD = "lastSeen";
	public static final String PIN_FIELD = "pin";
	public static final String RECOVERYPIN_FIELD = "recoverypin";
	public static final String KEYSHARE_FIELD = "keyshare";
	public static final String DEVICE_KEY_FIELD = "deviceKey";
	public static final String PUBLICKEY_FIELD = "publickey";
	public static final String EMAILISSUED_FIELD = "email_issued";
	public static final String ENROLLED_FIELD = "enrolled";
	public static final String ENABLED_FIELD = "enabled";
	public static final String SESSION_FIELD = "sessionToken";
	public static final String PINCOUNTER_FIELD = "pincounter";
	public static final String PINBLOCK_DATE = "pinblockDate";

	public User(String username, String password, String pin, BigInteger secret, BigInteger deviceKey, PublicKey publicKey) {
		if (!checkInput(pin, publicKey))
			throw new KeyshareException(KeyshareError.MALFORMED_INPUT);

		setString(USERNAME_FIELD, username);
		setString(PASSWORD_FIELD, password);
		setString(PIN_FIELD, pin);
		setString(RECOVERYPIN_FIELD, "");

		setInteger(PINCOUNTER_FIELD, 0);
		setString(KEYSHARE_FIELD, secret.toString(16));
		setString(DEVICE_KEY_FIELD, deviceKey.toString(16));

		setString(PUBLICKEY_FIELD, GsonUtil.getGson().toJson(publicKey));
		this.publicKey = publicKey;

		setBoolean(ENROLLED_FIELD, false);
		setBoolean(ENABLED_FIELD, true);
		setBoolean(EMAILISSUED_FIELD, false);
		saveIt();
	}

	private boolean checkInput(String pin, PublicKey publicKey) {
		return publicKey != null && publicKey.getN() != null && publicKey.getG() != null
				&& pin != null
				&& pin.length() > 44; // Length of SHA256 in Base64 plus =\n
	}

	public User(String username, String password, String pin, PublicKey publicKey) {
		this(username, password, pin, new BigInteger(255, new SecureRandom()), BigInteger.ZERO, publicKey);
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
		boolean notExpired = getLong(LAST_SEEN_FIELD) +
				+ KeyshareConfiguration.getInstance().getSessionTimeout() * 60
				> System.currentTimeMillis()/1000;

		return valid && notExpired;
	}

	public long getLastSeen() {
		List<LogEntryRecord> list = getAll(LogEntryRecord.class).orderBy("time desc").limit(1);
		if (list.size() == 0)
			return 0;
		return list.get(0).getLong(LogEntryRecord.DATE_FIELD);
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
		return !KeyshareConfiguration.getInstance().getCheckUserEnrolled() || getBoolean(ENROLLED_FIELD);
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
		return new UserMessage(getUsername(), getSessionToken(), "" + getID(), isEnrolled(), isEnabled(), getEmailAddressIssued(), getEmailAddresses());
	}

	public String getPIN() {
		return getString(PIN_FIELD);
	}

	public void setPIN(String newPin) {
		setString(PIN_FIELD, newPin);
		saveIt();
	}

	public int getPinCounter() {
		return getInteger(PINCOUNTER_FIELD);
	}

	public void setPinCounter(int count) {
		setInteger(PINCOUNTER_FIELD, count);
	}

	public String getRecoveryPIN() {
		String pin = getString(RECOVERYPIN_FIELD);
		if (pin == null || pin.equals("")) {
			throw new KeyshareException(KeyshareError.NO_RECOVERY);
		}
		return pin;
	}

	public void setRecoveryPIN(String newPin) {
		setString(RECOVERYPIN_FIELD, newPin);
		saveIt();
	}

	public boolean checkAndCountPin(String pin) {
	    return checkAndCountPin(pin, getPIN());
    }

    public boolean checkAndCountRecoveryPin(String pin) {
	    return checkAndCountPin(pin, getRecoveryPIN());
	}

	public boolean checkAndCountPin(String pin, String toCheck) {
		int pinCounter = getPinCounter();

		boolean correct = toCheck.equals(pin);
		pinCounter++;
		setPinCounter(pinCounter);

		if(correct) {
			addLog(LogEntryType.PIN_CHECK_SUCCESS);
			resetPinCounter();
		} else {
			addLog(LogEntryType.PIN_CHECK_FAILED, getPinTriesRemaining());

			if(pinCounter >= MAX_PIN_TRIES) {
				incrementPinblock();
				int block = getPinblockRelease();
				logger.warn("PIN tried too often, disabled user {} for {} seconds", getUsername(), block);
				addLog(LogEntryType.PIN_CHECK_BLOCKED, block);
			}
		}

		saveIt();
		return correct;
	}

	public int getPinTriesRemaining() {
		return MAX_PIN_TRIES - getPinCounter();
	}

	public BigInteger getKeyshare() {
		BigInteger key = new BigInteger(getString(KEYSHARE_FIELD), 16);
		BigInteger delta = new BigInteger(getString(DEVICE_KEY_FIELD), 16);
		System.out.println("Key: " + key.toString() + "delta: " + delta.toString());
		return key.subtract(delta);
	}

	public void setDeviceKey(BigInteger delta) {
		setString(DEVICE_KEY_FIELD, delta.toString(16));
		saveIt();
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
			throw new KeyshareException(KeyshareError.UNEXPECTED_REQUEST);
		}

		ProofP proof = pbuilder.build(challenge, getPublicKey());

		// Ensure that we can only answer one challenge (lest we totally break security)
		pbuilder = null;
		addLog(LogEntryType.IRMA_SESSION);

		return proof;
	}

	public void addLog(LogEntryType event) {
		add(new LogEntryRecord(event));
	}

	public void addLog(LogEntryType event, int param) {
		add(new LogEntryRecord(event, param));
	}

	public void addEmailAddress(String email) {
		addEmailAddress(email, false); // TODO not used? remove verified column?
	}

	public void addEmailAddress(String email, boolean verified) {
		// Don't insert duplicate email addresses
		if (EmailAddress.count(EmailAddress.EMAIL_ADDRESS_FIELD + " = ? and user_id = ?", email, getID()) == 0)
			add(new EmailAddress(email));
	}

	public boolean removeEmailAddress(String email) {
		List<EmailAddress> list = get(EmailAddress.class, EmailAddress.EMAIL_ADDRESS_FIELD + " = ?", email);
		return list.size() != 0 && list.get(0).delete();
	}

	public List<EmailAddress> getEmailAddresses() {
		return getAll(EmailAddress.class);
	}

	public LogEntryList getLogs(long start) {
		List<LogEntryRecord> records = get(LogEntryRecord.class,
						LogEntryRecord.DATE_FIELD + " <= ?", start)
				.orderBy(LogEntryRecord.DATE_FIELD + " desc")
				.limit(10 + 1); // Fetch one extra for its timestamp

		// Fetch the items that would be displayed on the previous page,
		// to find out the timestamp of the first item
		List<LogEntryRecord> prevRecords = get(LogEntryRecord.class,
						LogEntryRecord.DATE_FIELD + " > ?", start)
				.orderBy(LogEntryRecord.DATE_FIELD + " asc")
				.limit(10);

		ArrayList<LogEntry> lst = new ArrayList<>();
		int count = 0;
		boolean hasNext = false;

		for(LogEntryRecord entry : records)
			lst.add(new LogEntry(entry));

		if (lst.size() == 11) {
			lst.remove(10);
			hasNext = true;
		}

		Long next = hasNext ? records.get(10).getTime() : null;
		Long prev = prevRecords.size() != 0 ? prevRecords.get(prevRecords.size()-1).getTime() : null;
		return new LogEntryList(lst, prev, next);
	}

	private void resetPinCounter() {
		setPinCounter(0);
	}

	public void setEnabled(boolean enabled) {
		if(enabled) {
			addLog(LogEntryType.IRMA_ENABLED);
			resetPinCounter();
		} else {
			addLog(LogEntryType.IRMA_BLOCKED);
		}

		setBoolean(ENABLED_FIELD, enabled);
		saveIt();
	}

	public void setEmailAddressIssued() {
		setBoolean(EMAILISSUED_FIELD, true);
		saveIt();
	}

	public boolean getEmailAddressIssued() {
		return EmailAddress.count("user_id = ?", getID()) == 0 // Check if there is anything to issue
			|| getBoolean(EMAILISSUED_FIELD);
	}

	private int getPinblockLevel() {
		return Math.max(0, getPinCounter() - MAX_PIN_TRIES + 1);
	}

	public void incrementPinblock() {
		long duration = BACKOFF_START * 60 *  (
				pow(BACKOFF_FACTOR, getPinblockLevel() - 1)
		);
		setLong(PINBLOCK_DATE, System.currentTimeMillis()/1000 + duration);
	}

	public int getPinblockRelease() {
		if (getPinblockLevel() == 0)
			return 0;

		long date = getLong(PINBLOCK_DATE);
		return Math.max(0, (int)(date - System.currentTimeMillis()/1000));
	}

	public boolean isPinBlocked() {
		return getPinblockRelease() > 0;
	}

	public boolean isEnabled() {
		return getBoolean(ENABLED_FIELD) && !isPinBlocked();
	}

	public void unregister() {
		deleteCascade();
	}


	/**
	 * Returns a^b.
	 */
	// http://stackoverflow.com/a/20984477
	public static long pow(long a, int b)
	{
		if (b == 0)        return 1;
		if (b == 1)        return a;
		if (b%2 == 0)      return     pow (a * a, b/2); // even a=(a^2)^b/2
		else               return a * pow (a * a, b/2); // odd  a=a*(a^2)^b/2
	}

	public boolean old() {
		return Pattern.compile("^.+@.+\\..+$").matcher(getUsername()).find();
	}
}
