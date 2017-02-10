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
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@SuppressWarnings({"unused", "FieldCanBeLocal"})
public class KeyshareConfiguration {
	private static Logger logger = LoggerFactory.getLogger(KeyshareConfiguration.class);

	private static final String filename = "config.json";
	private static KeyshareConfiguration instance;

	private String server_name = "IRMATestCloud";

	private String jwt_privatekey = "sk.der";
	private String jwt_publickey = "pk.der";

	private int pinExpiry = 900; // 15 minutes

	private String mail_user = "";
	private String mail_password = "";
	private String mail_host = "";
	private String mail_from = "";

	private String server_url = "";

	private String enroll_done_url = "/irma_keyshare_server/enroll_done/";

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

	public String getMailUser() {
		return mail_user;
	}

	public String getMailPassword() {
		return mail_password;
	}

	public String getMailHost() {
		return mail_host;
	}

	public String getMailFrom() {
		return mail_from;
	}

	public String getUrl() {
		if (server_url.endsWith("/")) return server_url;
		else return server_url + "/";
	}

	public String getApiUrl() {
		if (!server_url.endsWith("/"))
			return server_url + "/" + "irma_keyshare_server/api";
		else
			return server_url + "irma_keyshare_server/api";
	}

	public String getEnrollDoneUrl() {
		return enroll_done_url;
	}

	private static PublicKey parsePublicKey(byte[] bytes) throws KeyManagementException {
		try {
			if (bytes == null || bytes.length == 0)
				throw new KeyManagementException("Could not read public key");

			X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);

			return KeyFactory.getInstance("RSA").generatePublic(spec);
		} catch (NoSuchAlgorithmException|InvalidKeySpecException e) {
			throw new KeyManagementException(e);
		}
	}

	public static PrivateKey parsePrivateKey(byte[] bytes) throws KeyManagementException {
		try {
			if (bytes == null || bytes.length == 0)
				throw new KeyManagementException("Could not read private key");

			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);

			return KeyFactory.getInstance("RSA").generatePrivate(spec);
		} catch (NoSuchAlgorithmException|InvalidKeySpecException e) {
			throw new KeyManagementException(e);
		}
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
			try {
				jwtPrivateKey = parsePrivateKey(getResource(jwt_privatekey));
			} catch (KeyManagementException|IOException e) {
				throw new RuntimeException(e);
			}
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
			try {
				jwtPublicKey = parsePublicKey(getResource(jwt_publickey));
			} catch (KeyManagementException|IOException e) {
				throw new RuntimeException(e);
			}
		}

		return jwtPublicKey;
	}

	public SignatureAlgorithm getJwtAlgorithm() {
		return SignatureAlgorithm.RS256;
	}
}
