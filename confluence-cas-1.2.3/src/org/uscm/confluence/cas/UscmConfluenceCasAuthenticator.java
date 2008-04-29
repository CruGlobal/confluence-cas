package org.uscm.confluence.cas;

import java.security.Principal;
import java.util.Map;

import org.apache.log4j.Logger;
import org.jasig.cas.client.validation.Assertion;
import org.soulwing.confluence.cas.ConfluenceCasAuthenticator;

import com.atlassian.confluence.user.UserAccessor;
import com.atlassian.user.User;

public class UscmConfluenceCasAuthenticator extends ConfluenceCasAuthenticator {
  private static final long serialVersionUID = 1L;

  private static Logger log = Logger
      .getLogger(UscmConfluenceCasAuthenticator.class);

  @SuppressWarnings("unchecked")
  @Override
  protected Principal getUser(Assertion assertion) {
    Principal user = null;
    String username = assertion.getPrincipal().getId();
    Map<String, String> attributes = assertion.getAttributes();
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
    //log.warn("returning user");
    return user;
  }
}
