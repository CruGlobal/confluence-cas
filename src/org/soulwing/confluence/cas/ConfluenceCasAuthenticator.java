/*
/*
 * ConfluenceCasAuthenticator.java
 * Created: 2 March 2006
 *
 * Copyright (C) 2006 Carl Harris, Jr.  All rights reserved.
 * This software is OSI Certified Open Source Software licensed under the
 * the GNU Lesser General Public License (LGPL).  The full text of the LGPL
 * is available at http://www.gnu.org/copyleft/lesser.html.
 *
 * This software was derived substantially from the CasSeraphAuthenticator
 * class developed by Ingomar Otter (ingomar.otter@valtech.de) as modified by
 * Jason Shao (jayshao.rutgers.edu).  Thanks to the both of them for making
 * their work freely available to public.
 *
 * This software extends the ConfluenceAuthenticator class developed by
 * Atlassian (www.atlassian.com) for their Confluence wiki software.  
 */

package org.soulwing.confluence.cas;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.web.filter.AbstractCasFilter;

import com.atlassian.confluence.user.ConfluenceAuthenticator;
import com.atlassian.seraph.auth.AuthenticatorException;


/**
 * Subclass of ConfluenceAuthenticator that provides CAS authentication for
 * Confluence.
 *
 * @author ingomar.otter
 * @author jayshao
 * @author Carl Harris
 * 
 */
public class ConfluenceCasAuthenticator extends ConfluenceAuthenticator {

  private static final Logger log = 
      Logger.getLogger(ConfluenceCasAuthenticator.class);


  /**
   * Gets the authenticated user name.  If CAS has not been bypassed, this
   * method returns the CAS-authenticated username and additionally sets the
   * LOGGED_IN_KEY and LOGGED_OUT_KEY attributes as specified by
   * ConfluenceAuthenticator.  Otherwise the return value is the result of
   * delegating to the superclass.
   * 
   * This method overrides ConfluenceAuthenticator.getUser.
   *
   * @param request the subject HTTP request
   * @param response the subject HTTP response
   * 
   * @return Principal instance that corresponds to the value of the 
   *     CAS_FILTER_USER session attribute if this attribute if CAS has not been 
   *     bypassed and the CAS_FILTER_USER session attribute exists in 
   *     <code>request</code>.  Otherwise, delegates to the superclass and the 
   *     returns the resulting Principal.
   */
  public Principal getUser(HttpServletRequest request, 
                           HttpServletResponse response) {

    if (ConfluenceCasFilter.isBypassed(request)) {
      log.debug("delegating to ConfluenceAuthenticator (CASFilter bypassed)");
      return super.getUser(request, response);
    }

    Principal user = null;
    try {
      Assertion assertion = (Assertion) request.getSession().getAttribute(AbstractCasFilter.CONST_ASSERTION);
      if (assertion != null) {
        user = getUser(assertion);
        if (user != null) {
          request.getSession().setAttribute(LOGGED_IN_KEY, user);
          request.getSession().setAttribute(LOGGED_OUT_KEY, null);
        } else {
          log.error("getUser() for CAS user " + assertion.getPrincipal().getId() + " returned null");
          return null;
        }
      }
      else {
        // no CAS user... use default implementation.
        log.debug("delegating to ConfluenceAuthenticator (no CAS user)");
      }
      if (user == null) {
        user = super.getUser(request, response);
      }
    } catch (Exception ex) {
      log.warn("Exception: " + ex.toString(), ex);
    }
    return user;

  }

  protected Principal getUser(Assertion assertion) {
    Principal user = null;
    String username = assertion.getPrincipal().getId();
    if (username != null) {
      user = getUser(username);
    } else {
      log.error("CAS Assertion contained null principal!");
    }
    return user;
  }

  /**
   * Performs a login validation check on behalf of Confluence. This method 
   * overrides ConfluenceAuthenticator.login.  It delegates to the 
   * <code>login(request, response, username, password, cookie)</code> overload
   * for this method.
   *
   * @param request subject HTTP request
   * @param response subject HTTP response
   * @param username username collected from the user
   * @param password password collected from the user
   * @return <code>true</code> if the specified user and password are valid.
   */
  public boolean login(HttpServletRequest request,
                       HttpServletResponse response,
                       String username, String password) {

    boolean result = false;
    try {
      result = login(request, response, username, password, false);
    } catch (AuthenticatorException ex) {
      log.error("login exception: " + ex.toString(), ex);
    }
    return result;
  }

  /**
   * Performs a login validation check on behalf of Confluence. This method 
   * overrides ConfluenceAuthenticator.login.
   *
   * @param request subject HTTP request
   * @param response subject HTTP response
   * @param username username collected from the user
   * @param password password collected from the user
   * @param cookie flag of unknown purpose that will be passed thru to 
   *     ConfluenceAuthenticator.login if we delegate this request.
   * @return <code>true</code> if CAS has not been bypassed and the 
   *     CAS_FILTER_USER session attribute exists in <code>request</code>.  
   *     Otherwise, delegatesto the superclass and the returns the resulting
   *     boolean.
   */
  public boolean login(HttpServletRequest request,
                       HttpServletResponse response,
                       String username, String password, boolean cookie) 
      throws AuthenticatorException {

    if (ConfluenceCasFilter.isBypassed(request)) {
      log.debug("delegating to ConfluenceAuthenticator (CASFilter bypassed)");
      return super.login(request, response, username, password, cookie);
    }
    Assertion assertion = (Assertion)
        request.getSession().getAttribute(AbstractCasFilter.CONST_ASSERTION);
    if (assertion != null) {
      return true;
    }
    else {
      log.debug("delegating to ConfluenceAuthenticator (no CAS assertion)");
      return super.login(request, response, username, password, cookie);
    }
  }
     
}
