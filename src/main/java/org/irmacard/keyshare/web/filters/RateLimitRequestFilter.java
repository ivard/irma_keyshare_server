package org.irmacard.keyshare.web.filters;

import org.irmacard.keyshare.web.KeyshareConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Rate limit filter, that denies the request if the most recent request to the same
 * path was too recent.
 */
@RateLimit
public class RateLimitRequestFilter implements ContainerRequestFilter {
	private static Logger logger = LoggerFactory.getLogger(RateLimitRequestFilter.class);

	// Keeps track of requests, structure: URL path -> IP -> time that this IP last accessed the path
	private static ConcurrentHashMap<String, ConcurrentHashMap<String, Long>> requests = new ConcurrentHashMap<>();

	@Context
	private HttpServletRequest servletRequest;

	@Override
	public void filter(ContainerRequestContext context) throws IOException {
		KeyshareConfiguration conf = KeyshareConfiguration.getInstance();

		// An IP can access the ratelimited path only once every so many seconds
		int limit = conf.getRateLimit();
		if (limit == 0)
			return;

		String ip = conf.getClientIp(servletRequest);
		String path = servletRequest.getPathInfo();
		Long time = System.currentTimeMillis();

		// Add a new submap to the map for this path if it has not yet been accessed before
		if (!requests.containsKey(path))
			requests.put(path, new ConcurrentHashMap<String, Long>());

		ConcurrentHashMap<String, Long> accesses = requests.get(path);
		if (!accesses.containsKey(ip)) {
			// This IP has never accessed this path before, just store the current time
			accesses.put(ip, time);
		} else {
			if (accesses.get(ip) - time > limit * 1000) { // factor 1000 as time is in milliseconds
				accesses.put(ip, time);
			} else {
				// This path was accessed too recently
				accesses.put(ip, time);
				logger.warn("Denying request to {} from {}!", path, ip);
				throw new WebApplicationException(Response.status(Response.Status.SERVICE_UNAVAILABLE).build());
			}
		}
	}
}
