package org.irmacard.keyshare.web;

import org.irmacard.keyshare.web.email.EmailVerificationRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@WebListener
public class BackgroundJobManager implements ServletContextListener {
	private static Logger logger = LoggerFactory.getLogger(BackgroundJobManager.class);
	static private ScheduledExecutorService scheduler;

    public static ScheduledExecutorService getScheduler() {
        if (scheduler == null) {
            synchronized (BackgroundJobManager.class) {
                if (scheduler == null) {
                    scheduler = Executors.newScheduledThreadPool(2);
                }
            }
        }
        return scheduler;
    }

	@Override
	public void contextInitialized(ServletContextEvent event) {
		logger.info("Setting up database cleanup cron task");
        ScheduledExecutorService sched = getScheduler();

		sched.scheduleAtFixedRate(new Runnable() {
			@Override public void run() {
				try {
					logger.warn("Deleting expired email verifications");
					KeyshareApplication.openDatabase();
					EmailVerificationRecord.delete(
							"(time_verified IS NULL AND time_created + timeout < ?) "
									+ "OR (time_verified IS NOT NULL AND time_verified + validity < ?)",
							System.currentTimeMillis() / 1000,
							System.currentTimeMillis() / 1000
					);
				} catch (Exception e) {
					logger.error("Failed to run database cleanup cron task:");
					e.printStackTrace();
				}
			}
		}, 6, 6, TimeUnit.HOURS);
	}

	@Override
	public void contextDestroyed(ServletContextEvent event) {
		getScheduler().shutdownNow();
	}
}
