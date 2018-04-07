/*
 * GsonJerseyProvider.java
 *
 * Copyright (c) 2015, Sietse Ringers, Radboud University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the IRMA project nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package org.irmacard.keyshare.web;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.api.common.util.GsonUtilBuilder;
import org.irmacard.api.common.util.IssuerIdentifierSerializer;
import org.irmacard.api.common.util.PublicKeyIdentifierSerializer;
import org.irmacard.credentials.info.IssuerIdentifier;
import org.irmacard.credentials.info.PublicKeyIdentifier;
import org.irmacard.keyshare.common.exceptions.KeyshareError;
import org.irmacard.keyshare.common.exceptions.KeyshareException;

import javax.servlet.ServletConfig;
import javax.ws.rs.Consumes;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Provider;
import java.io.*;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;

@Provider
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class GsonJerseyProvider implements MessageBodyWriter<Object>, MessageBodyReader<Object> {
	private static final String UTF_8 = "UTF-8";

	private static final Gson gson1;
	private static final Gson gson2;

	@Context
	private ServletConfig servletConfig;

	static {
		gson1 = GsonUtil.getGson();

		// TODO move these to GsonUtil when old protocol is deprecated
		GsonUtilBuilder builder = new GsonUtilBuilder();
		builder.addTypeAdapter(IssuerIdentifier.class, new IssuerIdentifierSerializer());
		builder.addTypeAdapter(PublicKeyIdentifier.class, new PublicKeyIdentifierSerializer());
		gson2 = builder.create();
	}

	@Override
	public boolean isReadable(Class<?> type, Type genericType,
							  Annotation[] annotations, MediaType mediaType) {
		return true;
	}

	@Override
	public Object readFrom(Class<Object> type, Type genericType,
						   Annotation[] annotations, MediaType mediaType,
						   MultivaluedMap<String, String> httpHeaders, InputStream entityStream)
			throws IOException {
		try (InputStreamReader streamReader = new InputStreamReader(entityStream, UTF_8)) {
			if (servletConfig.getServletName().equals(KeyshareApplication.VERSION2)) {
				return gson2.fromJson(streamReader, genericType);
			} else {
				Object o = gson1.fromJson(streamReader, genericType);
				System.out.println(gson1.toJson(o, genericType));
				return o;
			}
		} catch (JsonParseException e) {
			throw new KeyshareException(KeyshareError.MALFORMED_INPUT, e.getMessage());
		}
	}

	@Override
	public boolean isWriteable(Class<?> type, Type genericType,
							   Annotation[] annotations, MediaType mediaType) {
		return true;
	}

	@Override
	public long getSize(Object object, Class<?> type, Type genericType,
						Annotation[] annotations, MediaType mediaType) {
		return -1;
	}

	@Override
	public void writeTo(Object object, Class<?> type, Type genericType,
						Annotation[] annotations, MediaType mediaType,
						MultivaluedMap<String, Object> httpHeaders,
						OutputStream entityStream) throws IOException,
			WebApplicationException {
		try (OutputStreamWriter writer = new OutputStreamWriter(entityStream, UTF_8)) {
			if (servletConfig.getServletName().equals(KeyshareApplication.VERSION2)) {
				gson2.toJson(object, genericType, writer);
			} else {
				gson1.toJson(object, genericType, writer);
				System.out.println(gson1.toJson(object, genericType));
			}
		}
	}
}
