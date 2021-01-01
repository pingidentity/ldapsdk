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
package com.unboundid.ldap.sdk.persist;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.LDAPException;



/**
 * This class provides test coverage for the {@code LDAPPersistException} class.
 */
public class LDAPPersistExceptionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the LDAP persist exception constructor which
   * takes an LDAP exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithLDAPException()
         throws Exception
  {
    String[] referralURLs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server2.example.com/dc=example,dc=com"
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true),
      new Control("1.2.3.6", true, new ASN1OctetString())
    };

    LDAPPersistException e = new LDAPPersistException(new LDAPException(
         ResultCode.NO_SUCH_OBJECT, "foo", "dc=example,dc=com", referralURLs,
         controls, new Exception()));
    assertNotNull(e);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "foo");

    assertEquals(e.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(e.getMatchedDN());
    assertEquals(new DN(e.getMatchedDN()),
         new DN("dc=example,dc=com"));

    assertNotNull(e.getReferralURLs());
    assertEquals(e.getReferralURLs().length, 2);

    assertNotNull(e.getResponseControls());
    assertEquals(e.getResponseControls().length, 3);

    assertNotNull(e.getCause());
  }



  /**
   * Provides test coverage for the LDAP persist exception constructor which
   * takes just a message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithMessage()
         throws Exception
  {
    LDAPPersistException e = new LDAPPersistException("foo");
    assertNotNull(e);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "foo");

    assertEquals(e.getResultCode(), ResultCode.LOCAL_ERROR);

    assertNull(e.getMatchedDN());

    assertNotNull(e.getReferralURLs());
    assertEquals(e.getReferralURLs().length, 0);

    assertNotNull(e.getResponseControls());
    assertEquals(e.getResponseControls().length, 0);

    assertNull(e.getCause());
  }



  /**
   * Provides test coverage for the LDAP persist exception constructor which
   * takes a message and a cause.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithMessageAndNonNullCause()
         throws Exception
  {
    LDAPPersistException e = new LDAPPersistException("foo", new Exception());
    assertNotNull(e);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "foo");

    assertEquals(e.getResultCode(), ResultCode.LOCAL_ERROR);

    assertNull(e.getMatchedDN());

    assertNotNull(e.getReferralURLs());
    assertEquals(e.getReferralURLs().length, 0);

    assertNotNull(e.getResponseControls());
    assertEquals(e.getResponseControls().length, 0);

    assertNotNull(e.getCause());
  }



  /**
   * Provides test coverage for the LDAP persist exception constructor which
   * takes a message and a cause, using a {@code null} cause.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithMessageAndNullCause()
         throws Exception
  {
    LDAPPersistException e = new LDAPPersistException("foo", null);
    assertNotNull(e);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "foo");

    assertEquals(e.getResultCode(), ResultCode.LOCAL_ERROR);

    assertNull(e.getMatchedDN());

    assertNotNull(e.getReferralURLs());
    assertEquals(e.getReferralURLs().length, 0);

    assertNotNull(e.getResponseControls());
    assertEquals(e.getResponseControls().length, 0);

    assertNull(e.getCause());
  }



  /**
   * Provides coverage for the {@code getExceptionMessage} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetExceptionMessage()
         throws Exception
  {
    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/dc=example,dc=com",
      "ldap://ds2.example.com:389/dc=example,dc=com"
    };

    final Control[] responseControls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5")
    };

    final LDAPPersistException lpe = new LDAPPersistException(
         new LDAPException(ResultCode.NO_SUCH_OBJECT,
              "The entry does not exist", "dc=example,dc=com",
              referralURLs, responseControls, new NullPointerException("NPE")));

    final String defaultMessage = lpe.getExceptionMessage(false, false);
    assertFalse(defaultMessage.contains("trace="));
    assertFalse(defaultMessage.contains("cause="));

    final String messageWithCause = lpe.getExceptionMessage(true, false);
    assertFalse(messageWithCause.contains("trace="));
    assertTrue(messageWithCause.contains("cause="));

    final String messageWithTrace = lpe.getExceptionMessage(false, true);
    assertTrue(messageWithTrace.contains("trace="));
    assertTrue(messageWithTrace.contains("cause="));
  }
}
