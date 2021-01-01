/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides test coverage for the {@code LDAPReferralException}
 * class.
 */
public class LDAPReferralExceptionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the default constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultConstructor()
         throws Exception
  {
    LDAPReferralException e = new LDAPReferralException();

    assertNotNull(e);

    assertEquals(e.getLDAPResultCode(), 10);

    assertNotNull(e.getMessage());

    assertNull(e.getLDAPErrorMessage());

    assertNull(e.getMatchedDN());

    assertNotNull(e.getURLs());
    assertEquals(e.getURLs().length, 0);
  }



  /**
   * Provides test coverage for the constructor which takes a message, result
   * code, and server message but no URLs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithoutURLs()
         throws Exception
  {
    LDAPReferralException e = new LDAPReferralException("message",
         10, "server message");

    assertNotNull(e);

    assertEquals(e.getLDAPResultCode(), 10);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "message");

    assertNotNull(e.getLDAPErrorMessage());
    assertEquals(e.getLDAPErrorMessage(), "server message");

    assertNull(e.getMatchedDN());

    assertNotNull(e.getURLs());
    assertEquals(e.getURLs().length, 0);
  }



  /**
   * Provides test coverage for the constructor which takes a message, result
   * code, and URLs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithURLs()
         throws Exception
  {
    String[] refs =
    {
      "ldap://server1.example.com:389/dc=example,dc=com",
      "ldap://server2.example.com:389/dc=example,dc=com"
    };

    LDAPReferralException e = new LDAPReferralException("message",
         10, refs);

    assertNotNull(e);

    assertEquals(e.getLDAPResultCode(), 10);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "message");

    assertNull(e.getLDAPErrorMessage());

    assertNull(e.getMatchedDN());

    assertNotNull(e.getURLs());
    assertEquals(e.getURLs().length, 2);
  }



  /**
   * Provides test coverage for the constructor which takes an SDK LDAP
   * exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithSDKException()
         throws Exception
  {
    String[] refs =
    {
      "ldap://server1.example.com:389/dc=example,dc=com",
      "ldap://server2.example.com:389/dc=example,dc=com"
    };

    LDAPReferralException e = new LDAPReferralException(new LDAPException(
         ResultCode.REFERRAL, "referral", "dc=example,dc=com", refs, null,
         null));

    assertNotNull(e);

    assertEquals(e.getLDAPResultCode(), 10);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "referral");

    assertNotNull(e.getLDAPErrorMessage());
    assertEquals(e.getLDAPErrorMessage(), "referral");

    assertNotNull(e.getMatchedDN());
    assertEquals(e.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(e.getURLs());
    assertEquals(e.getURLs().length, 2);
  }
}
