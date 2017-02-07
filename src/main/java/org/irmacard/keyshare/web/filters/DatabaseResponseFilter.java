package org.irmacard.keyshare.web.filters;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DatabaseResponseFilter implements ContainerResponseFilter {
	private static Logger logger = LoggerFactory.getLogger(DatabaseResponseFilter.class);

	@Override
	public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
		logger.warn("End of request!");
		//CloudApplication.closeDatabase();
	}
}
