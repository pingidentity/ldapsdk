/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (C) 2007-2021 Ping Identity Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (GPLv2 only)
 * or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
package com.unboundid.ldap.sdk;



import java.nio.charset.StandardCharsets;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.schema.Schema;



/**
 * This class provides a set of test cases for the {@code RDNNameValuePair}
 * class.
 */
public final class RDNNameValuePairTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the basic behavior of the {@code RDNNameValuePair} class when no
   * {@code Schema} object is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameValuePairWithoutSchema()
         throws Exception
  {
    final RDNNameValuePair p = new RDNNameValuePair("givenName",
         new ASN1OctetString("foo"), null);

    assertNotNull(p.getAttributeName());
    assertEquals(p.getAttributeName(), "givenName");

    assertNotNull(p.getNormalizedAttributeName());
    assertEquals(p.getNormalizedAttributeName(), "givenname");

    // The second time should use a cached version.
    assertNotNull(p.getNormalizedAttributeName());
    assertEquals(p.getNormalizedAttributeName(), "givenname");

    assertNotNull(p.getAttributeValue());
    assertEquals(p.getAttributeValue(), "foo");

    assertNotNull(p.getAttributeValueBytes());
    assertEquals(p.getAttributeValueBytes(),
         "foo".getBytes(StandardCharsets.UTF_8));

    assertNotNull(p.getRawAttributeValue());
    assertEquals(p.getRawAttributeValue(), new ASN1OctetString("foo"));

    assertNotNull(p.toString());
    assertEquals(p.toString(), "givenName=foo");

    // The second time should use a cached version.
    assertNotNull(p.toString());
    assertEquals(p.toString(), "givenName=foo");

    final StringBuilder buffer = new StringBuilder();
    p.toString(buffer, false);
    assertEquals(buffer.toString(), p.toString());

    assertNotNull(p.toMinimallyEncodedString());
    assertEquals(p.toMinimallyEncodedString(), "givenName=foo");

    assertNotNull(p.toNormalizedString());
    assertEquals(p.toNormalizedString(), "givenname=foo");

    // The second time should use a cached version.
    assertNotNull(p.toNormalizedString());
    assertEquals(p.toNormalizedString(), "givenname=foo");
  }



  /**
   * Tests the basic behavior of the {@code RDNNameValuePair} class when a
   * non-{@code null} {@code Schema} object is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameValuePairWithSchema()
         throws Exception
  {
    final RDNNameValuePair p = new RDNNameValuePair("givenName",
         new ASN1OctetString("foo"), Schema.getDefaultStandardSchema());

    assertNotNull(p.getAttributeName());
    assertEquals(p.getAttributeName(), "givenName");

    assertNotNull(p.getNormalizedAttributeName());
    assertEquals(p.getNormalizedAttributeName(), "givenname");

    // The second time should use a cached version.
    assertNotNull(p.getNormalizedAttributeName());
    assertEquals(p.getNormalizedAttributeName(), "givenname");

    assertNotNull(p.getAttributeValue());
    assertEquals(p.getAttributeValue(), "foo");

    assertNotNull(p.getAttributeValueBytes());
    assertEquals(p.getAttributeValueBytes(),
         "foo".getBytes(StandardCharsets.UTF_8));

    assertNotNull(p.getRawAttributeValue());
    assertEquals(p.getRawAttributeValue(), new ASN1OctetString("foo"));

    final StringBuilder buffer = new StringBuilder();
    buffer.append("xxx");
    p.toString(buffer, false);
    assertEquals(buffer.toString(), "xxx" + p.toString());

    buffer.setLength(0);
    p.toString(buffer, false);
    assertEquals(buffer.toString(), p.toString());

    buffer.setLength(0);
    p.toString(buffer, true);
    assertEquals(buffer.toString(), p.toMinimallyEncodedString());

    assertNotNull(p.toString());
    assertEquals(p.toString(), "givenName=foo");

    assertNotNull(p.toMinimallyEncodedString());
    assertEquals(p.toMinimallyEncodedString(), "givenName=foo");

    assertNotNull(p.toNormalizedString());
    assertEquals(p.toNormalizedString(), "givenname=foo");

    // The second time should use a cached version.
    assertNotNull(p.toNormalizedString());
    assertEquals(p.toNormalizedString(), "givenname=foo");
  }



  /**
   * Tests the {@code compare}, {@code compareTo}, and {@code equals} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareAndEquals()
         throws Exception
  {
    final RDNNameValuePair p1 = new RDNNameValuePair("givenName",
         new ASN1OctetString("foo"), Schema.getDefaultStandardSchema());

    // Test identity equality.
    assertTrue(p1.equals(p1));
    assertEquals(p1.compareTo(p1), 0);
    assertEquals(p1.compare(p1, p1), 0);
    p1.hashCode();

    // Test logical equivalence with exact case matching.
    final RDNNameValuePair p2 = new RDNNameValuePair("givenName",
         new ASN1OctetString("foo"), Schema.getDefaultStandardSchema());
    assertTrue(p1.equals(p2));
    assertTrue(p2.equals(p1));
    assertEquals(p1.compareTo(p2), 0);
    assertEquals(p1.compare(p1, p2), 0);
    assertEquals(p2.compareTo(p1), 0);
    assertEquals(p2.compare(p2, p1), 0);
    p2.hashCode();

    // Test logical equivalence with different case matching.
    final RDNNameValuePair p3 = new RDNNameValuePair("GivenName",
         new ASN1OctetString("Foo"), Schema.getDefaultStandardSchema());
    assertTrue(p1.equals(p3));
    assertTrue(p3.equals(p1));
    assertEquals(p1.compareTo(p3), 0);
    assertEquals(p1.compare(p1, p3), 0);
    assertEquals(p3.compareTo(p1), 0);
    assertEquals(p3.compare(p3, p1), 0);
    p3.hashCode();

    // Test with the same attribute name but a different value.
    final RDNNameValuePair p4 = new RDNNameValuePair("givenName",
         new ASN1OctetString("bar"), Schema.getDefaultStandardSchema());
    assertFalse(p1.equals(p4));
    assertFalse(p4.equals(p1));
    assertTrue(p1.compareTo(p4) > 0);
    assertTrue(p1.compare(p1, p4) > 0);
    assertTrue(p4.compareTo(p1) < 0);
    assertTrue(p4.compare(p4, p1) < 0);
    p4.hashCode();

    // Test with the same value but a completely different attribute name.
    final RDNNameValuePair p5 = new RDNNameValuePair("sn",
         new ASN1OctetString("foo"), Schema.getDefaultStandardSchema());
    assertFalse(p1.equals(p5));
    assertFalse(p5.equals(p1));
    assertTrue(p1.compareTo(p5) < 0);
    assertTrue(p1.compare(p1, p5) < 0);
    assertTrue(p5.compareTo(p1) > 0);
    assertTrue(p5.compare(p5, p1) > 0);
    p5.hashCode();

    // Test with the same value but an attribute name that just has a digit
    // appended to it.
    final RDNNameValuePair p6 = new RDNNameValuePair("givenName2",
         new ASN1OctetString("foo"), Schema.getDefaultStandardSchema());
    assertFalse(p1.equals(p6));
    assertFalse(p6.equals(p1));
    assertTrue(p1.compareTo(p6) < 0);
    assertTrue(p1.compare(p1, p6) < 0);
    assertTrue(p6.compareTo(p1) > 0);
    assertTrue(p6.compare(p6, p1) > 0);
    p6.hashCode();

    // Test with a completely different attribute name aand a completely
    // different value.
    final RDNNameValuePair p7 = new RDNNameValuePair("cn",
         new ASN1OctetString("bar"), Schema.getDefaultStandardSchema());
    assertFalse(p1.equals(p7));
    assertFalse(p7.equals(p1));
    assertTrue(p1.compareTo(p7) > 0);
    assertTrue(p1.compare(p1, p7) > 0);
    assertTrue(p7.compareTo(p1) < 0);
    assertTrue(p7.compare(p7, p1) < 0);

    assertFalse(p1.equals(null));
    assertFalse(p1.equals("not an RDN name-value pair"));
  }
}
