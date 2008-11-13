/*
 * Copyright 2006 The JA-SIG Collaborative. All rights reserved. See license
 * distributed with this file and available online at
 * http://www.uportal.org/license.html
 */
package org.jasig.cas.client.util;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

/**
 * Utility class to retrieve a Filter from a Spring-managed configuration file.
 * Based on the FilterToBeanProxy class in Acegi Security (but simplified)
 * 
 * @author Scott Battaglia
 * @version $Revision: 1.4 $ $Date: 2006/07/13 13:11:26 $
 * @since 3.0
 */
public class FilterToBeanProxy implements Filter {

    private Filter filter;

    public void destroy() {
        // nothing to do
    }

    public final void doFilter(final ServletRequest request,
        final ServletResponse response, final FilterChain chain)
        throws IOException, ServletException {
      HttpServletRequest httpRequest = (HttpServletRequest)request;
      if (httpRequest.getRequestURI().indexOf("plugins/servlet") == -1 && httpRequest.getRequestURI().indexOf("rpc/xmlrpc") == -1 ) {
        this.filter.doFilter(request, response, chain);
      } else {
        chain.doFilter(request, response);
      }
    }

    public final void init(final FilterConfig filterConfig)
        throws ServletException {
        doInit(filterConfig);
    }

    protected ApplicationContext getContext(FilterConfig filterConfig) {
        return WebApplicationContextUtils
            .getRequiredWebApplicationContext(filterConfig.getServletContext());
    }

    private final void doInit(final FilterConfig filterConfig)
        throws ServletException {
        final String targetBean = filterConfig.getInitParameter("targetBean");

        if (CommonUtils.isBlank(targetBean)) {
            throw new ServletException(
                "init-parameter missing: targetBean is required.");
        }

        final ApplicationContext ctx = this.getContext(filterConfig);

        if (!ctx.containsBean(targetBean)) {
            throw new ServletException("targetBean '" + targetBean
                + "' not found in context");
        }

        this.filter = (Filter) ctx.getBean(targetBean, Filter.class);
    }
}
