package org.irmacard.keyshare.web.filters;

import org.irmacard.keyshare.web.KeyshareApplication;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;

public class DatabaseResponseFilter implements ContainerResponseFilter {
	@Override
	public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
		KeyshareApplication.closeDatabase();
	}
}
