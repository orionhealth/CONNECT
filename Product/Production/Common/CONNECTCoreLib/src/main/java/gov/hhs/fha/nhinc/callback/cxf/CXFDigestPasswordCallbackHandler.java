/*
 *Copyright (c) 2014, United States Government, as represented by the Secretary of Health and Human Services.
 *All rights reserved.
 *
 *Redistribution and use in source and binary forms, with or without
 *modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above
 *      copyright notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the documentation
 *      and/or other materials provided with the distribution.
 *    * Neither the name of the United States Government nor the
 *      names of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 *THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 *ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *DISCLAIMED. IN NO EVENT SHALL THE UNITED STATES GOVERNMENT BE LIABLE FOR ANY
 *DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
package gov.hhs.fha.nhinc.callback.cxf;

import gov.hhs.fha.nhinc.messaging.service.decorator.DigestAuthenticationServiceEndpointDecorator;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.apache.ws.security.WSPasswordCallback;
import org.springframework.util.Assert;

public class CXFDigestPasswordCallbackHandler implements CallbackHandler {

	private static final Logger LOG = Logger.getLogger(CXFDigestPasswordCallbackHandler.class);
	
    /**
     * Digest authentication callback handler retrieves the password from the hard coded (Java) system property    
     */
    public final void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
    
    	Assert.notEmpty(callbacks, "The callback object must be provided");
    	Assert.isInstanceOf(WSPasswordCallback.class, callbacks[0], "The callback was not of type WSPasswordCallback");
    	
    	final WSPasswordCallback pc = (WSPasswordCallback) callbacks[0];
    	
    	final String webserviceUser = System.getProperty(DigestAuthenticationServiceEndpointDecorator.WEB_SERVICE_USER_SYSTEM_PROPERTY);
    	final String webservicePassword = System.getProperty(DigestAuthenticationServiceEndpointDecorator.WEB_SERVICE_PASSWORD_SYSTEM_PROPERTY);
		
    	if (StringUtils.isBlank(webserviceUser)){
			LOG.warn(String.format("The WebService user system property (%s) was not configured. This is likely to mean the web service call will fail"
					, DigestAuthenticationServiceEndpointDecorator.WEB_SERVICE_USER_SYSTEM_PROPERTY));
			return;
		}
    	
    	if (StringUtils.isBlank(webservicePassword)){
			LOG.warn(String.format("The WebService password system property (%s) was not configured. This is likely to mean the web service call will fail"
					, DigestAuthenticationServiceEndpointDecorator.WEB_SERVICE_PASSWORD_SYSTEM_PROPERTY));
			return;
		}
    	
    	final String userInWebServiceCall = pc.getIdentifier();
    	
    	if (!userInWebServiceCall.equals(webserviceUser)){
    		throw new SecurityException(String.format("The user in the web service call (%s) does not match the user configured with the system property (%s)", userInWebServiceCall, webserviceUser));
    	}
		
    	pc.setPassword(webservicePassword);
    }

}
