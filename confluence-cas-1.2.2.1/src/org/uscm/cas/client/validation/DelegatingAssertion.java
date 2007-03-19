package org.uscm.cas.client.validation;

import java.util.Map;

import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.client.validation.Assertion;

public class DelegatingAssertion implements Assertion {

	private Assertion standardAssertion;
	private Map<String, String> attributes;
	
	public DelegatingAssertion(Assertion standardAssertion, Map<String, String> attributes) {
		this.standardAssertion = standardAssertion;
		this.attributes = attributes;
	}
	
	public Map getAttributes() {
		return attributes;
	}

	public Principal getPrincipal() {
		return standardAssertion.getPrincipal();
	}

	public String getProxyTicketFor(Service service) {
		return standardAssertion.getProxyTicketFor(service);
	}

}
