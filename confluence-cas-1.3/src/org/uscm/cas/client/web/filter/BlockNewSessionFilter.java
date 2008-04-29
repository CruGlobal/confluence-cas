package org.uscm.cas.client.web.filter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Locale;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The 3.0.0M2 Cas Client uses response.encodeURL when generating a redirect to cas.
 * This causes problems when the session is brand new, because a ";jsessionid=xxxxx"
 * gets tacked on to the end, but when the client returns, the filter builds the 
 * service name without that parameter (because the session is not brand new, and is identified by a cookie), and 
 * the cas server complains that the ticket's service does not match the service against
 * which the filter tries to validate it.
 * 
 * Our workaround is simply to cause a redirect on the first request of a brand
 * new session.  If the browser doesn't accept cookies, this should still work,
 * because response.encodeURL will be consistent accross all requests.
 * 
 * @author matthew.drees
 *
 */
public class BlockNewSessionFilter implements Filter {

  public void destroy() {
  }

  public void doFilter(ServletRequest request, ServletResponse response,
      FilterChain fc) throws IOException, ServletException {

    HttpServletRequest httpRequest = (HttpServletRequest) request;
    HttpServletResponse httpResponse = (HttpServletResponse) response;

    if (httpRequest.getSession().isNew()) {
      StringBuffer buffer = httpRequest.getRequestURL();
      String queryString = httpRequest.getQueryString();
      if (queryString != null) {
        buffer.append('?').append(queryString);
      }
      httpResponse.sendRedirect(httpResponse.encodeRedirectURL(buffer.toString()));
    } else {
      fc.doFilter(request, response);
    }
  }

  public void init(FilterConfig config) throws ServletException {

  }

  
  
}
