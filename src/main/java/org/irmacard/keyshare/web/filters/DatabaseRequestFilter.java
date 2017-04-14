package org.irmacard.keyshare.web.filters;

import org.irmacard.keyshare.web.KeyshareApplication;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import java.io.IOException;

/*
 * See: https://jersey.java.net/documentation/latest/filters-and-interceptors.html
 * for some decent documentation on how to work with filters
 */
public class DatabaseRequestFilter implements ContainerRequestFilter {
	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {
		KeyshareApplication.openDatabase();
	}
}
