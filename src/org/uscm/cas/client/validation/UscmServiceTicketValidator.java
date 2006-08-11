package org.uscm.cas.client.validation;

import java.util.Map;

import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.AssertionImpl;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.jasig.cas.client.validation.ValidationException;
import org.uscm.cas.client.util.XmlUtilsExtensions;

public class UscmServiceTicketValidator extends Cas20ServiceTicketValidator {

  @Override
  protected Assertion parseResponse(String response) throws ValidationException {
    Assertion standardAssertion = super.parseResponse(response);
    Map<String, String> attributes = XmlUtilsExtensions.getTextForElements(response, "attributes");
    return new AssertionImpl(standardAssertion.getPrincipal(), attributes, standardAssertion.getProxyGrantingTicketId());
  }
}
