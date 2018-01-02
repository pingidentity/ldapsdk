/*
 * Copyright 2015-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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



import java.util.ArrayList;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;



/**
 * This class provides a set of test cases for the test SASL bind request.  This
 * is primarily intended for getting code coverage.
 */
public final class TestSASLBindRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a bind request without any credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindRequestWithoutCredentials()
         throws Exception
  {
    TestSASLBindRequest bindRequest = new TestSASLBindRequest();

    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getSASLMechanismName());
    assertEquals(bindRequest.getSASLMechanismName(), "TEST");

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests a bind request with credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindRequestWithCredentials()
         throws Exception
  {
    TestSASLBindRequest bindRequest = new TestSASLBindRequest(
         new ASN1OctetString("saslCredentials"),
         new Control("1.2.3.4"),
         new Control("1.2.3.5", false, new ASN1OctetString("controlValue")));

    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getSASLMechanismName());
    assertEquals(bindRequest.getSASLMechanismName(), "TEST");

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }
}
