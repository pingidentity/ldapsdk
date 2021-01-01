/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
import com.unboundid.ldap.listener.InMemoryDirectoryServer;



/**
 * This class provides a set of unit tests for the generic SASL bind request
 * class.
 */
public final class GenericSASLBindRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for a valid bind request.
   *
   * @throws  Exception  If an exception.
   */
  @Test()
  public void testValidRequest()
         throws Exception
  {
    final String credString = "\u0000dn:cn=Directory Manager\u0000password";

    final GenericSASLBindRequest r = new GenericSASLBindRequest(null, "PLAIN",
         new ASN1OctetString(credString)).duplicate();

    assertNull(r.getBindDN());

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "PLAIN");

    assertNotNull(r.getCredentials());
    assertEquals(r.getCredentials().stringValue(), credString);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    final InMemoryDirectoryServer ds = getTestDS();

    final LDAPConnection conn = ds.getConnection();

    final BindResult bindResult = conn.bind(r);
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

    conn.close();
  }



  /**
   * Provides test coverage for the toString method for a request that does not
   * have any credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToStringWithoutCredentials()
         throws Exception
  {
    final GenericSASLBindRequest r = new GenericSASLBindRequest(
         "cn=Directory Manager", "FOO", null);

    assertNotNull(r.getBindDN());
    assertEquals(new DN(r.getBindDN()), new DN("cn=Directory Manager"));

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "FOO");

    assertNull(r.getCredentials());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Provides test coverage for the toString method for a request that has a
   * single control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToStringWithSingleControl()
         throws Exception
  {
    final GenericSASLBindRequest r = new GenericSASLBindRequest(
         null, "EXTERNAL", null, new Control("1.2.3.4"));

    assertNull(r.getBindDN());

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "EXTERNAL");

    assertNull(r.getCredentials());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Provides test coverage for the toString method for a request that has
   * multiple controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToStringWithMultipleControls()
         throws Exception
  {
    final GenericSASLBindRequest r = new GenericSASLBindRequest(
         null, "EXTERNAL", null, new Control("1.2.3.4"),
         new Control("1.2.3.5"));

    assertNull(r.getBindDN());

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "EXTERNAL");

    assertNull(r.getCredentials());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }
}
