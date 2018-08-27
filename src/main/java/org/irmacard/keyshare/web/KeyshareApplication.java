/*
 * Copyright (c) 2015, Wouter Lueks
 * Copyright (c) 2015, Sietse Ringers
 * Copyright (c) 2015, Fabian van den Broek
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the IRMA project nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.irmacard.keyshare.web;

import org.glassfish.jersey.server.ResourceConfig;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.info.IdemixKeyStoreDeserializer;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.DescriptionStoreDeserializer;
import org.irmacard.credentials.info.updater.Updater;
import org.irmacard.keyshare.web.filters.DatabaseRequestFilter;
import org.irmacard.keyshare.web.filters.DatabaseResponseFilter;
import org.irmacard.keyshare.web.filters.RateLimitRequestFilter;
import org.irmacard.mno.web.exceptions.KeyshareExceptionMapper;
import org.javalite.activejdbc.Base;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.ApplicationPath;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

@ApplicationPath("/")
public class KeyshareApplication extends ResourceConfig {
    private static Logger logger = LoggerFactory.getLogger(KeyshareApplication.class);

    public static final String VERSION2 = "irma_keyshare2_server";

    public KeyshareApplication() {
        KeyshareConfiguration conf = KeyshareConfiguration.getInstance();

        if (!DescriptionStore.isInitialized() || !IdemixKeyStore.isInitialized()) {
            loadOrUpdateIrmaConfiguration(true);

            if (conf.schemeManager_update_uri != null) {
                BackgroundJobManager.getScheduler().scheduleAtFixedRate(new Runnable() {
                    @Override public void run() {
                        loadOrUpdateIrmaConfiguration(false);
                    }
                }, 1, 1, TimeUnit.HOURS);
            }
        }

        // register Gson
        register(GsonJerseyProvider.class);

        // register exception handler, for converting and then returning exceptions as JSON output
        register(KeyshareExceptionMapper.class);

        // Base verification class for testing token authorizations
        register(VerificationResource.class);

        // Specific authorization methods
        register(PinResource.class);

        register(ProveResource.class);

        register(DatabaseRequestFilter.class);
        register(DatabaseResponseFilter.class);
        register(RateLimitRequestFilter.class);

        register(WebClientResource.class);

        register(ClientResource.class);

        //Recovery
        register(RecoveryManager.class);

        // Enable the Historian class, if an events webhook is set.
        if (conf.events_webhook_uri != null) {
            Historian.getInstance().enable(
                    conf.events_webhook_uri,
                    conf.events_webhook_authorizationToken);
        }

        logger.info("Running keyshare application");
        openDatabase();
        closeDatabase();
    }

    private void loadOrUpdateIrmaConfiguration(boolean initial) {
        KeyshareConfiguration conf = KeyshareConfiguration.getInstance();
        URI CORE_LOCATION;
        try {
            CORE_LOCATION = KeyshareApplication.class.getClassLoader().getResource("/irma_configuration/").toURI();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        boolean updated = false;

        if (conf.schemeManager_update_uri != null) {
            logger.info("Updating irma_configuration from {} ...",
                    conf.schemeManager_update_uri);
            try {
                updated = Updater.update(
                        conf.schemeManager_update_uri,
                        Paths.get(CORE_LOCATION).toString(),
                        conf.getSchemeManagerPublicKeyString());
            } catch(Exception e) {
                logger.error("Update failed:", e);
            }
        }

        try {
            if (initial || updated) {
                DescriptionStore.initialize(new DescriptionStoreDeserializer(CORE_LOCATION));
                IdemixKeyStore.initialize(new IdemixKeyStoreDeserializer(CORE_LOCATION));
            }
        } catch (Exception e) {
            logger.error("Store initialization failed:", e);
        }
    }


    public static void openDatabase() {
        if(!Base.hasConnection()) {
            logger.warn("Opening database connection");
            Base.open("java:comp/env/jdbc/irma_keyshare");
        }
    }

    public static void closeDatabase() {
        logger.warn("Closing database connection");
        Base.close();
    }
}
