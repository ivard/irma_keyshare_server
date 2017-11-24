package org.irmacard.keyshare.web;

import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.client.HttpClient;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.HttpResponse;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.Condition;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.lang.UnsupportedOperationException;
import java.io.UnsupportedEncodingException;
import java.io.IOException;

// Historian is a singleton thread which collects and sends events
// to an outside HTTP server.  It is disabled by default.  Enable with
// the enable() method.
public class Historian implements Runnable {
    private static  Historian instance;

    private static Logger logger = LoggerFactory.getLogger(Historian.class);

    // synchronization
    private Thread thread;
    private Lock lock;
    private Condition cond;

    // the data -- should only be accessed when lock is held
    private class Event {
        public void AddToRequest(SubmitRequest req) {
            throw new UnsupportedOperationException();
        }
    }
    private class LoginEvent extends Event{
        public Date When;
        public boolean Success;
        public boolean WithOTP;

        public LoginEvent(Date When, boolean Success, boolean WithOTP) {
            this.When = When; this.Success = Success; this.WithOTP = WithOTP;
        }
        @Override public void AddToRequest(SubmitRequest req) {
            req.Logins.add(this);
        }
    }
    private class RegistrationEvent extends Event {
        public Date When;
        public boolean Double;

        public RegistrationEvent(Date When, boolean Double)  {
            this.When = When; this.Double = Double;
        }
        @Override public void AddToRequest(SubmitRequest req) {
            req.Registrations.add(this);
        }
    }
    private class EmailVerifiedEvent extends Event {
        public Date When;

        public EmailVerifiedEvent(Date When) {
            this.When = When;
        }
        @Override public void AddToRequest(SubmitRequest req) {
            req.EmailsVerified.add(this);
        }
    }
    private class UnregistrationEvent extends Event {
        public Date When;

        public UnregistrationEvent(Date When) {
            this.When = When;
        }
        @Override public void AddToRequest(SubmitRequest req) {
            req.Unregistrations.add(this);
        }
    }
    private class PinBlockedEvent extends Event {
        public Date When;

        public PinBlockedEvent(Date When) {
            this.When = When;
        }
        @Override public void AddToRequest(SubmitRequest req) {
            req.PinsBlocked.add(this);
        }
    }

    private class SubmitRequest {
        ArrayList<LoginEvent> Logins;
        ArrayList<RegistrationEvent> Registrations;
        ArrayList<EmailVerifiedEvent> EmailsVerified;
        ArrayList<UnregistrationEvent> Unregistrations;
        ArrayList<PinBlockedEvent> PinsBlocked;

        public SubmitRequest(ArrayList<Event> events) {
            this.Logins = new ArrayList<LoginEvent>();
            this.Registrations = new ArrayList<RegistrationEvent>();
            this.EmailsVerified = new ArrayList<EmailVerifiedEvent>();
            this.Unregistrations = new ArrayList<UnregistrationEvent>();
            this.PinsBlocked = new ArrayList<PinBlockedEvent>();

            for (Event event: events) {
                event.AddToRequest(this);
            }
        }
    }
    private ArrayList<Event> events = new ArrayList<Event>();
    
    // configuration
    private boolean enabled = false;
    private String uri;
    private String authorizationToken;

    // json dumper
    private Gson gson;

    private Historian() {
        this.lock = new ReentrantLock();
        this.cond = lock.newCondition();
        this.gson = new GsonBuilder().setDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").create();
    }

    public static Historian getInstance() {
        if (instance == null) {
            synchronized (Historian.class) {
                if (instance == null) {
                    instance = new Historian();
                }
            }
        }
        return instance;
    }

    // Pushes the data.
    private boolean pushEvents(String payload) {
        try {
            HttpClient httpClient = HttpClientBuilder.create().build();
            HttpPost httpPost = new HttpPost(this.uri);
            if (this.authorizationToken != null) {
                httpPost.setHeader("Authorization",
                                    "Basic " + this.authorizationToken);
            }
            List<NameValuePair> params = new ArrayList<NameValuePair>(1);
            params.add(new BasicNameValuePair("events", payload));
            httpPost.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode != 200) {
                logger.warn("Failed to push: HTTP code "
                                + Integer.toString(statusCode));
                return false;
            }
        } catch (UnsupportedEncodingException e) {
            return false;
        } catch (IOException e) {
            return false;
        }
        return true;
    }

    public void run() {
        logger.info("Historian worker thread started");
        String toSend = null;

        int eventsSent = 0;

        boolean pushAttempted = false;
        boolean pushWasSuccessful = false;

        while (true) {
            this.lock.lock();
            try {
                if (!this.enabled) break;

                // Did we succesfully push some data?  If so, we need to clear
                // it from the lists.
                if (pushAttempted) {
                    pushAttempted = false;
                    if (pushWasSuccessful) {
                        events.subList(0, eventsSent).clear();
                    }
                }

                // Wait for a new batch of data.
                if (!pushWasSuccessful || events.size() == 0) {
                    this.cond.await();
                }

                eventsSent = this.events.size();
                if (eventsSent != 0) {
                    toSend = gson.toJson(new SubmitRequest(this.events));
                    pushAttempted = true;
                }
            } catch (InterruptedException e ) { 
            } finally {
                this.lock.unlock();
            }

            if (toSend != null) {
                pushWasSuccessful = pushEvents(toSend);
                toSend = null;
            }
        }
    }

    public void disable() {
        if (!this.enabled) return;
        this.enabled = false;
        this.lock.lock();
        try {
            this.cond.signal();
        } finally {
            this.lock.unlock();
        }
    }

    public void enable(String uri, String authorizationToken) {
        if (enabled) {
            throw new IllegalStateException("Already enabled");
        }

        this.enabled = true;
        this.thread = new Thread(this);
        this.authorizationToken = authorizationToken;
        this.uri = uri;

        thread.start();
    }

    public void recordLogin(boolean success, boolean withOTP) {
        if (!this.enabled)
            return;
        this.lock.lock();
        try {
            events.add(new LoginEvent(new Date(), success, withOTP));
            this.cond.signal();
        } finally {
            this.lock.unlock();
        }
    }

    public void recordRegistration(boolean doubleRegistration) {
        if (!this.enabled)
            return;
        this.lock.lock();
        try {
            events.add(new RegistrationEvent(new Date(), doubleRegistration));
            this.cond.signal();
        } finally {
            this.lock.unlock();
        }
    }

    public void recordEmailVerified() {
        if (!this.enabled)
            return;
        this.lock.lock();
        try {
            events.add(new EmailVerifiedEvent(new Date()));
            this.cond.signal();
        } finally {
            this.lock.unlock();
        }
    }

    public void recordPinBlocked() {
        if (!this.enabled)
            return;
        this.lock.lock();
        try {
            events.add(new PinBlockedEvent(new Date()));
            this.cond.signal();
        } finally {
            this.lock.unlock();
        }
    }

    public void recordUnregistration() {
        if (!this.enabled)
            return;
        this.lock.lock();
        try {
            events.add(new UnregistrationEvent(new Date()));
            this.cond.signal();
        } finally {
            this.lock.unlock();
        }
    }
}

