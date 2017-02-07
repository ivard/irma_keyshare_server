package org.irmacard.mno.web.exceptions;

import org.irmacard.keyshare.common.exceptions.KeyshareErrorMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

/**
 * Convert an exception to a response for the client of the server
 */
public class KeyshareExceptionMapper implements ExceptionMapper<Throwable> {
	private static Logger logger = LoggerFactory.getLogger(KeyshareExceptionMapper.class);

	@Override
	public Response toResponse(Throwable ex) {
		KeyshareErrorMessage message = new KeyshareErrorMessage(ex);

		logger.info("Exception:");
		logger.info("{} {}, description: {}, message {}", message.getStatus(),
				message.getError(),
				message.getDescription(),
				message.getMessage());

		logger.debug(KeyshareErrorMessage.getExceptionStacktrace(ex));

		return Response.status(message.getStatus())
				.entity(message)
				.type(MediaType.APPLICATION_JSON)
				.build();
	}
}
