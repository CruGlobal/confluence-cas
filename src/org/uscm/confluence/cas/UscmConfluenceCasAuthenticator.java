package org.uscm.confluence.cas;

import java.security.Principal;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.jasig.cas.client.util.AbstractCasFilter;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.integration.atlassian.ConfluenceCasAuthenticator;

import com.atlassian.confluence.user.UserAccessor;
import com.atlassian.user.User;

public class UscmConfluenceCasAuthenticator extends ConfluenceCasAuthenticator {
  private static final long serialVersionUID = 1L;

  private static Logger log = Logger
      .getLogger(UscmConfluenceCasAuthenticator.class);

  @SuppressWarnings("unchecked")
  @Override
  public Principal getUser(final HttpServletRequest request, final HttpServletResponse response) {
    final HttpSession session = request.getSession();

    if (session != null) {
    // user already exists
        if (session.getAttribute(ConfluenceCasAuthenticator.LOGGED_IN_KEY) != null) {
            log.info("Session found; user already logged in.");
            return (Principal) session.getAttribute(LOGGED_IN_KEY);
        }

        final Assertion assertion = (Assertion) session.getAttribute(AbstractCasFilter.CONST_CAS_ASSERTION);

        if (assertion != null) {
          Map<String, String> attributes = assertion.getPrincipal().getAttributes();
          String username = assertion.getPrincipal().getName();
          Principal user = null;
          String ssoGuid = attributes.get("ssoGuid").toLowerCase();

          if (ssoGuid != null) {
            //log.warn("about to call getUser");
            user = getUser(ssoGuid);
            if (user == null) {
              //log.warn("user query returned null");
              String[] groups;
              String password;
              if (attributes.get("emplid") != null
                  && !attributes.get("emplid").equals("")) {
                groups = new String[2];
                groups[1] = "ccc-employee";
                password = attributes.get("emplid");
              } else {
                groups = new String[1];
                password = attributes.get("firstName");
              }
              groups[0] = "confluence-users";

              UserAccessor userAccessor = getUserAccessor();
              user = userAccessor.addUser(ssoGuid, // Username
                  password,
                  username, attributes.get("firstName") + " "
                      + attributes.get("lastName"), groups);
              
              if (user == null) {
                log.error("Added user " + ssoGuid + ", but failed to find it!");
              } else {
                //log.warn(user.toString());
                userAccessor.saveUser((User)user);
              }
            }
          } else {
            log.error("CAS Assertion contained no ssoGuid!");
          }

        request.getSession().setAttribute(LOGGED_IN_KEY, user);
        request.getSession().setAttribute(LOGGED_OUT_KEY, null);
        return user;
      }
    }

    return super.getUser(request, response);
  }
}
