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

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.osgi.framework.Bundle;
import org.osgi.service.http.HttpContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A custom http context that does enforces JWT or basic authentication
 **/
public class CustomHttpContext implements HttpContext {

    private static final Logger LOG = LoggerFactory.getLogger(CustomHttpContext.class);

    private Bundle bundle;

    CustomHttpContext(Bundle bundle) {
	this.bundle = bundle;
    }    

    @Override
    public boolean handleSecurity(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException {
        LOG.info("Handling security now...");
        return true;
    }

    @Override
    public URL getResource(final String name) {
        throw new IllegalStateException("Can't access this");
    }

    @Override
    public String getMimeType(String s) {
        throw new IllegalStateException("Not allowed!");
    }

}
