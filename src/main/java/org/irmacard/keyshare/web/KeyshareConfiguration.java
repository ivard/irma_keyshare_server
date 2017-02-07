package org.irmacard.keyshare.web;

import com.google.gson.JsonSyntaxException;
import org.irmacard.api.common.util.GsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.jsonwebtoken.SignatureAlgorithm;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

@SuppressWarnings({"unused"})
public class KeyshareConfiguration {
	private static Logger logger = LoggerFactory.getLogger(KeyshareConfiguration.class);

	private static final String filename = "config.json";
	private static KeyshareConfiguration instance;

	private String server_name = "IRMATestCloud";

	private int pinExpiry = 900; // 15 minutes

	private transient PrivateKey jwtPrivateKey;
	private transient PublicKey jwtPublicKey;

	public KeyshareConfiguration() {}

	/**
	 * Reloads the configuration from disk so that {@link #getInstance()} returns the updated version
	 */
	public static void load() {
		// TODO: GSon seems to always be lenient (i.e. allow comments in the JSon), even though
		// the documentation states that by default, it is not lenient. Why is this? Could change?
		try {
			String json = new String(getResource(filename));
			instance = GsonUtil.getGson().fromJson(json, KeyshareConfiguration.class);
		} catch (IOException |JsonSyntaxException e) {
			logger.warn("Could not load configuration file. Using default values (may not work!)");
			e.printStackTrace();
			instance = new KeyshareConfiguration();
		}

		logger.info("Cloud configuration: {}", instance);
	}

	public static KeyshareConfiguration getInstance() {
		if (instance == null)
			load();

		return instance;
	}

	public int getPinExpiry() {
		return pinExpiry;
	}

	public void setPinExpiry(int pinExpiry) {
		this.pinExpiry = pinExpiry;
	}

	public static byte[] getResource(String filename) throws IOException {
		URL url = KeyshareConfiguration.class.getClassLoader().getResource(filename);
		if (url == null)
			throw new IOException("Could not load file " + filename);

		URLConnection urlCon = url.openConnection();
		urlCon.setUseCaches(false);
		return convertSteamToByteArray(urlCon.getInputStream(), 2048);
	}

	public static byte[] convertSteamToByteArray(InputStream stream, int size) throws IOException {
		byte[] buffer = new byte[size];
		ByteArrayOutputStream os = new ByteArrayOutputStream();

		int line;
		while ((line = stream.read(buffer)) != -1) {
			os.write(buffer, 0, line);
		}
		stream.close();

		os.flush();
		os.close();
		return os.toByteArray();
	}

	@Override
	public String toString() {
		return GsonUtil.getGson().toJson(this);
	}

	public PrivateKey getJwtPrivateKey() {
		if (jwtPrivateKey == null) {
			KeyPairGenerator kpg;

			try {
				kpg = KeyPairGenerator.getInstance("RSA");
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
				return null;
			}

			kpg.initialize(4096);
			KeyPair kp = kpg.genKeyPair();
			jwtPrivateKey = kp.getPrivate();
			jwtPublicKey = kp.getPublic();
		}

		return jwtPrivateKey;
	}

	public String getServerName() {
		return server_name;
	}

	public void setServerName(String server_name) {
		this.server_name = server_name;
	}

	public PublicKey getJwtPublicKey() {
		if (jwtPublicKey == null) {
			getJwtPrivateKey();
		}

		return jwtPublicKey;
	}

	public SignatureAlgorithm getJwtAlgorithm() {
		return SignatureAlgorithm.RS256;
	}
}
