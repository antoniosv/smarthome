/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.eclipse.smarthome.auth.jwt.internal;

import java.io.IOException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Base64;
import java.util.StringTokenizer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.osgi.framework.Bundle;
import org.osgi.service.http.HttpContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
    

/**
 * A custom http context that does enforces JWT or basic authentication
 **/
public class CustomHttpContext implements HttpContext {

    private static final Logger LOG = LoggerFactory.getLogger(CustomHttpContext.class);
    private final Bundle bundle;
    private static KeyPair kp = null;

    CustomHttpContext(Bundle bundle) {
        this.bundle = bundle;
    }

    // @Override
    // public boolean handleSecurity(final HttpServletRequest request, final HttpServletResponse response)
    //         throws IOException {
    //     /* This implementation will change accordingly once class-loading problems are solved */
    //     LOG.info("Handling security now...");
    //     if (request.getHeader("Authorization") == null && request.getHeader("Cookie") == null) {
    //         // this should redirect to a login form
    //         LOG.info("No header -- Forbidden access!");
    //         response.addHeader("WWW-Authenticate", "Basic realm=\"Test Realm\"");
    //         response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    //         return false;
    //     }
    //     if (basicAuthenticated(request)) {
    //         LOG.info("Basic authentication successful!");
    //         return true;
    //     } else {
    //         response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    //         return false;
    //     }
    // }

    @Override
    public boolean handleSecurity(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
	//	LOG.info("cookie:" + request.getHeader("cookie"));
	//LOG.info("Counter: " + counter++);
	String freshToken = "";
	if(request.getHeader("Authorization") == null && request.getHeader("Cookie") == null) {
	    // this should redirect to a login form
	    LOG.info("No header -- Forbidden access!");
	    response.addHeader("WWW-Authenticate", "Basic realm=\"Test Realm\"");
	    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
	    return false;
	}
	try {
	    // try form authentication first
	    if(formAuthenticated(request)) {
		freshToken = "";
		// try {
		//     freshToken = generateJwt("baidi","admin");
		//     if(verifyJwt(freshToken)) {
		// 	LOG.info("token: " + freshToken);
		// 	response.addHeader("Set-Cookie", freshToken);
		//     } } catch(JOSEException e) {}		
	    }
	    else if(jwtAuthenticated(request)) {
		return true;		
	    } else if(basicAuthenticated(request)){
		LOG.info("trying basic auth now...");
		freshToken = "";
		try {
		    freshToken = generateJwt("baidi","admin");
		    response.addHeader("Set-Cookie", freshToken);
		    // if(verifyJwt(freshToken)) {
		    // 	LOG.info("token: " + freshToken);
		    // 	response.addHeader("Set-Cookie", freshToken);
		    // }
		} catch(JOSEException e) {}
		return true;
	    } else {
		LOG.info("Wrong credentials -- Forbidden access!");
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
		return false;
	    }
	} catch(JOSEException e) {
	    // skip
	}
	return false;
    }
    

    protected KeyPair getKeyPair() {
        if (kp == null) {
            try {
                KeyPairGenerator keyGenerator = null;
                keyGenerator = KeyPairGenerator.getInstance("RSA");
                keyGenerator.initialize(1024);
                kp = keyGenerator.genKeyPair();
            } catch (NoSuchAlgorithmException e) {
            }
        }
        return kp;
    }

    protected boolean basicAuthenticated(HttpServletRequest request) {
        request.setAttribute(AUTHENTICATION_TYPE, HttpServletRequest.BASIC_AUTH);

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null) {
            return false;
        }
        StringTokenizer tokenizer = new StringTokenizer(authHeader, " ");
        String authType = tokenizer.nextToken();
        if (!"Basic".equalsIgnoreCase(authType)) {
            return false;
        }

        // LOG.info("Authz header: " + authHeader);
        String usernameAndPassword = new String(Base64.getDecoder().decode(authHeader.substring(6).getBytes()));
        int userNameIndex = usernameAndPassword.indexOf(":");
        String username = usernameAndPassword.substring(0, userNameIndex);
        String password = usernameAndPassword.substring(userNameIndex + 1);

        boolean success = ((username.equals("admin") && password.equals("admin")));
        if (success) {
            request.setAttribute(REMOTE_USER, "admin");
        }
        return success;
    }

    @Override
    public URL getResource(final String name) {
        throw new IllegalStateException("Can't access this");
    }

    @Override
    public String getMimeType(String s) {
        throw new IllegalStateException("Not allowed!");
    }

    protected String generateJwt(String username, String claim) throws JOSEException {
        RSAPublicKey publicKey = (RSAPublicKey) getKeyPair().getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) getKeyPair().getPrivate();
        JWSSigner signer = new RSASSASigner(privateKey);

        // what's the key ID?
        JWSObject jwsObject = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("123").build(),
                new Payload(username));
        jwsObject.sign(signer);
        String token = jwsObject.serialize();
        return token;

    }

    // protected boolean verifyJwt(String token) throws JOSEException {
    //     boolean valid = false;
    //     RSAPublicKey publicKey = (RSAPublicKey) getKeyPair().getPublic();
    //     JWSObject jwsObject = null;

    //     if (token != null && !token.isEmpty()) {
    //         try {
    //             jwsObject = JWSObject.parse(token);
    //         } catch (ParseException e) {
    //             LOG.info("problem parsing token: " + token);
    //         }
    //     }
    //     LOG.info("Before verifier");
    //     JWSVerifier verifier = new RSASSAVerifier(publicKey);
    //     if (jwsObject != null) {
    //         valid = jwsObject.verify(verifier);
    //         LOG.info("Token Payload: " + jwsObject.getPayload().toString());
    //     }
    //     // valid = jwsObject.getPayload().toString().equals("baidi");
    //     return valid;
    // }

    protected boolean formAuthenticated(HttpServletRequest request) throws JOSEException {
        return false;
    }

    protected boolean jwtAuthenticated(HttpServletRequest request) throws JOSEException {
        String token = "";
        boolean verified;
        String authHeader = request.getHeader("Authorization");
        String cookie = request.getHeader("Cookie");

        LOG.info("trying to do jwt auth...");

        if (authHeader == null && cookie == null) {
            return false;
        }

        if (cookie != null) {
            token = cookie;
        } else if (authHeader != null) {
            StringTokenizer tokenizer = new StringTokenizer(authHeader, " ");
            String authType = tokenizer.nextToken();
            if ("Bearer".equalsIgnoreCase(authType)) {
                token = tokenizer.nextToken();
            }
        }
        LOG.info("raw token: " + token);
        // verified = verifyJwt(token);
	verified = false;
        if (verified) {
            LOG.info("JWT Authentication successful");
        } else {
            LOG.info("something didn't work in the jwt authentication");
        }
        return verified;
    }

    protected String extractUserBasic(HttpServletRequest request) {
        String authzHeader = request.getHeader("Authorization");
        String usernameAndPassword = new String(Base64.getDecoder().decode(authzHeader.substring(6).getBytes()));
        int userNameIndex = usernameAndPassword.indexOf(":");
        String username = usernameAndPassword.substring(0, userNameIndex);
        return username;
    }

    private boolean dbAuthenticate(String username, String password) throws Exception {
        // calculate password hash
        // query to database or file to check if username&password are valid
        return false;
    }

}
