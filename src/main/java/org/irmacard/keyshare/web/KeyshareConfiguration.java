package org.irmacard.keyshare.web;

import foundation.privacybydesign.common.BaseConfiguration;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.PrivateKey;
import java.security.PublicKey;

@SuppressWarnings({"unused", "FieldCanBeLocal"})
public class KeyshareConfiguration extends BaseConfiguration<KeyshareConfiguration> {
	private static Logger logger = LoggerFactory.getLogger(KeyshareConfiguration.class);

	static {
		BaseConfiguration.clazz = KeyshareConfiguration.class;
		BaseConfiguration.environmentVarPrefix = "IRMA_KEYSHARE_CONF_";
		BaseConfiguration.confDirEnvironmentVarName = "IRMA_KEYSHARE_CONF";
		BaseConfiguration.logger = KeyshareConfiguration.logger;
		BaseConfiguration.printOnLoad = true;
	}

	private String server_name = "IRMATestCloud";
	private String human_readable_name;

	private String jwt_privatekey = "sk.der";
	private String jwt_publickey = "pk.der";

	private int pinExpiry = 900; // 15 minutes

	private String mail_user = "";
	private String mail_password = "";
	private String mail_host = "";
	private String mail_from = "";
	private boolean mail_starttls_required = true;
	private int mail_port = 587;

	private String webclient_url = "";

	private String scheme_manager = "";
	private String email_issuer = "";
	private String email_credential = "";
	private String email_attribute = "";
	private String email_login_credential = "";
	private String email_login_attribute = "";

	private String login_email_subject = "Log in on the keyshare server";
	private String login_email_body = "Click on the link below to log in on the keyshare server.";
	private String register_email_subject = "Verify your email address";
	private String register_email_body = "To finish registering to the keyshare server, please click on the link below.";
	private String double_registration_email_subject = "Someone tried to re-register this email address";
	private String double_registration_email_body = "Someone tried to re-register this email address. Was this you? If so, you first need to unregister. If this wasn't you, you can ignore this message.";

	private boolean check_user_enrolled = true;

	private int session_timeout = 30;
	private int rate_limit = 3;

    private String client_ip_header = null;

	private String apiserver_publickey = "apiserver.der";
	private String schemeManager_publickey = "schemeManager.pk.pem";

	private transient PrivateKey jwtPrivateKey;
	private transient PublicKey jwtPublicKey;

    String events_webhook_uri = null;
    String events_webhook_authorizationToken = null;

    String schemeManager_update_uri = null;

	public KeyshareConfiguration() {}

	public static KeyshareConfiguration getInstance() {
		return (KeyshareConfiguration) BaseConfiguration.getInstance();
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

	public boolean getStarttlsRequired() { return mail_starttls_required; }

	public int getMailPort() {
		return mail_port;
	}

	public String getMailFrom() {
		return mail_from;
	}

	public String getWebclientUrl() {
		return webclient_url;
	}

	public boolean isHttpsEnabled() {
		return webclient_url.startsWith("https://");
	}

	public String getSchemeManager() {
		return scheme_manager;
	}

	public String getEmailIssuer() {
		return email_issuer;
	}

	public String getEmailCredential() {
		return email_credential;
	}

	public String getEmailAttribute() {
		return email_attribute;
	}

	public String getEmailLoginCredential() {
		return email_login_credential;
	}

	public String getEmailLoginAttribute() {
		return email_login_attribute;
	}

	public String getLoginEmailSubject() {
		return login_email_subject;
	}

	public String getLoginEmailBody() {
		return login_email_body;
	}

	public String getRegisterEmailSubject() {
		return register_email_subject;
	}

	public String getRegisterEmailBody() {
		return register_email_body;
	}

	public String getDoubleRegistrationEmailSubject() {
		return double_registration_email_subject;
	}

	public String getDoubleRegistrationEmailBody() {
		return double_registration_email_body;
	}

	public boolean getCheckUserEnrolled() { return check_user_enrolled; }

	public int getSessionTimeout() {
		return session_timeout;
	}

	public int getRateLimit() {
		return rate_limit;
	}

	public PrivateKey getJwtPrivateKey() {
		if (jwtPrivateKey == null) {
			try {
				jwtPrivateKey = getPrivateKey(jwt_privatekey);
			} catch (KeyManagementException e) {
				throw new RuntimeException(e);
			}
		}

		return jwtPrivateKey;
	}

	public String getServerName() {
		return server_name;
	}

	public String getHumanReadableName() {
		if (human_readable_name == null || human_readable_name.length() == 0)
			return server_name;
		else
			return human_readable_name;
	}

    public String getSchemeManagerPublicKeyString() {
        try {
            return new String(getResource(schemeManager_publickey));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

	public PublicKey getApiServerPublicKey() {
		try {
			return getPublicKey(apiserver_publickey);
		} catch (KeyManagementException e) {
			throw new RuntimeException(e);
		}
	}

	public PublicKey getJwtPublicKey() {
		if (jwtPublicKey == null) {
			try {
				jwtPublicKey = getPublicKey(jwt_publickey);
			} catch (KeyManagementException e) {
				throw new RuntimeException(e);
			}
		}

		return jwtPublicKey;
	}

	public SignatureAlgorithm getJwtAlgorithm() {
		return SignatureAlgorithm.RS256;
	}

	public String getClientIp(HttpServletRequest req) {
		String ret;
		if (this.client_ip_header != null) {
			ret = req.getHeader(this.client_ip_header);
			if (ret != null) {
				return ret;
			}
		}
		return req.getRemoteAddr();
	}
}
