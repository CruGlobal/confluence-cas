package org.uscm.cas.client.util;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jasig.cas.client.util.XmlUtils;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;

public class XmlUtilsExtensions {
  private static Log log = LogFactory.getLog(XmlUtilsExtensions.class);

  /**
   * Retrieve the subelements of the given element as a <code>Map</code> keyed
   * by subelement name.
   * Assumes there are no nested subelements, and that the xml is valid.
   * 
   * @param xmlAsString
   *          the xml response
   * @param element
   *          the element to look for
   * @return a map of element name to text value derived from subements of the
   *         given elements.
   */
  public static Map<String, String> getTextForElements(
      final String xmlAsString, final String element) {
    final Map<String, String> attributes = new HashMap<String, String>();
    final XMLReader reader = XmlUtils.getXmlReader();

    final DefaultHandler handler = new DefaultHandler() {

      private boolean insideElement = false;
      
      private StringBuffer buffer = new StringBuffer();

      public void startElement(final String uri, final String localName,
          final String qName, final Attributes attributes) throws SAXException {
        if (localName.equals(element)) {
          this.insideElement = true;
        }
        buffer.setLength(0);
      }

      public void endElement(final String uri, final String localName,
          final String qName) throws SAXException {
        if (localName.equals(element)) {
          this.insideElement = false;
        }
        if (insideElement) {
          attributes.put(localName, buffer.toString());
        }
      }

      public void characters(char[] ch, int start, int length)
          throws SAXException {
        if (this.insideElement) {
          this.buffer.append(ch, start, length);
        }
      }
    };

    reader.setContentHandler(handler);
    reader.setErrorHandler(handler);

    try {
      reader.parse(new InputSource(new StringReader(xmlAsString)));
    } catch (final Exception e) {
      log.error(e, e);
      return null;
    }

    return attributes;
  }

}
