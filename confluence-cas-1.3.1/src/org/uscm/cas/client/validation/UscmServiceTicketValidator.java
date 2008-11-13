package org.uscm.cas.client.validation;

import java.util.Map;

import org.apache.commons.httpclient.HttpClient;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.proxy.ProxyRetriever;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.jasig.cas.client.validation.ValidationException;
import org.uscm.cas.client.util.XmlUtilsExtensions;

public class UscmServiceTicketValidator extends Cas20ServiceTicketValidator {
  
  public UscmServiceTicketValidator(String casServerUrl, boolean renew, HttpClient httpClient, Service proxyCallbackUrl, ProxyGrantingTicketStorage proxyGrantingTicketStorage, ProxyRetriever proxyRetriever) {
		super(casServerUrl, renew, httpClient, proxyCallbackUrl,
				proxyGrantingTicketStorage, proxyRetriever);
	}

	public UscmServiceTicketValidator(String casServerUrl, boolean renew, HttpClient httpClient) {
		super(casServerUrl, renew, httpClient);
	}

	
	@Override
	protected Assertion getValidAssertionInternal(String response, String principal, String proxyGrantingTicketIou) throws ValidationException {
	    Assertion standardAssertion = super.getValidAssertionInternal(response, principal, proxyGrantingTicketIou);
	    Map<String, String> attributes = XmlUtilsExtensions.getTextForElements(response, "attributes");
	    return new DelegatingAssertion(standardAssertion, attributes);
	}
}
