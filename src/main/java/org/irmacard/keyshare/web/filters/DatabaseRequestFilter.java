package org.irmacard.keyshare.web.filters;

import java.io.IOException;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;

import org.irmacard.keyshare.web.KeyshareApplication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/*
 * See: https://jersey.java.net/documentation/latest/filters-and-interceptors.html
 * for some decent documentation on how to work with filters
 */
public class DatabaseRequestFilter implements ContainerRequestFilter {
	private static Logger logger = LoggerFactory.getLogger(DatabaseRequestFilter.class);

	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {
//		logger.warn("Before request, opening databse!");
		KeyshareApplication.openDatabase();
	}
}
