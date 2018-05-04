/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.eclipse.smarthome.auth.jwt.internal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.service.http.HttpContext;
import org.osgi.service.http.HttpService;
import org.osgi.util.tracker.ServiceTracker;

public class Activator implements BundleActivator {

    private Logger logger = LoggerFactory.getLogger(getClass().getName());

    BundleContext context;
    HttpService httpService;
    ServiceTracker<HttpService, HttpService> httpServiceTracker;
    
    @Override
    public void start(BundleContext context) {
	logger.info("HELLO");
	logger.info("starting Jersey TestActivator for servlet");
	httpServiceTracker = new ServiceTracker<HttpService, HttpService>(context, HttpService.class, null) {
		
		@Override
		public HttpService addingService(ServiceReference<HttpService> serviceRef) {
		    logger.info("registering test servlet");
		    httpService = super.addingService(serviceRef);
		    
		    HttpContext httpContext = new CustomHttpContext(context.getBundle());
		    
		    registerServlet(httpContext);
		    return httpService;
		}
		
		@Override
		public void removedService(ServiceReference<HttpService> ref, HttpService service) {
		    super.removedService(ref, service);
		    httpService = null;
		}
	    };
	httpServiceTracker.open();
    }
    
    @Override
    public void stop(BundleContext context) {
	//httpServiceTracker.close();
    }    
    
    private void registerServlet(HttpContext httpContext) {
	try {
	    httpService.registerServlet("/test", new TestServlet(), null, httpContext);
	} catch (Exception e) {
	    logger.info("Registering Jersey servlet failed");
	}
    }
}
