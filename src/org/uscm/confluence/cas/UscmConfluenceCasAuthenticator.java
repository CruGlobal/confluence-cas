package org.uscm.confluence.cas;

import java.security.Principal;
import java.util.Date;
import java.util.Map;

import org.apache.log4j.Logger;
import org.jasig.cas.client.validation.Assertion;
import org.soulwing.confluence.cas.ConfluenceCasAuthenticator;

import com.atlassian.confluence.user.UserAccessor;

public class UscmConfluenceCasAuthenticator extends ConfluenceCasAuthenticator {
  private static final long serialVersionUID = 1L;

  private static Logger log = Logger.getLogger(UscmConfluenceCasAuthenticator.class);
  
  @SuppressWarnings("unchecked")
  @Override
  protected Principal getUser(Assertion assertion) {
    Principal user = null;
    String username = assertion.getPrincipal().getId();
    if (username != null) {
      user = getUser(username);
      if (user == null) {
        Map<String, String> attributes = assertion.getAttributes();
        
        String[] groups;
        if (attributes.get("emplid") != null && !attributes.get("emplid").equals("") ) {
          groups = new String[2];
          groups[1] = "ccc-employee";
        } else {
          groups = new String[1];
        }
        groups[0] = "confluence-users";
        
        UserAccessor userAccessor = getUserAccessor();
        userAccessor.addUser(attributes.get("ssoGuid"), 
            String.valueOf(new Date().getTime()),
            username, 
            attributes.get("firstName") + " " + attributes.get("lastName"),
            groups);
      }
    } else {
      log.error("CAS Assertion contained null principal!");
    }
    return user;
}

  
}
