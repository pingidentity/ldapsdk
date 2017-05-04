/*
 * Copyright 2015-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2017 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the authentication failure reason
 * class.
 */
public final class AuthenticationFailureReasonTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for an authentication failure reason with a message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithMessage()
         throws Exception
  {
    AuthenticationFailureReason reason = new AuthenticationFailureReason(
         AuthenticationFailureReason.FAILURE_TYPE_ACCOUNT_NOT_USABLE,
         AuthenticationFailureReason.FAILURE_NAME_ACCOUNT_NOT_USABLE,
         "The account is expired.");

    assertNotNull(reason.toString());
    assertEquals(reason.toString(),
         "code=1\tname=account-not-usable\tmessage=The account is expired.");

    reason = new AuthenticationFailureReason(reason.toString());

    assertEquals(reason.getIntValue(),
         AuthenticationFailureReason.FAILURE_TYPE_ACCOUNT_NOT_USABLE);

    assertNotNull(reason.getName());
    assertEquals(reason.getName(),
         AuthenticationFailureReason.FAILURE_NAME_ACCOUNT_NOT_USABLE);

    assertNotNull(reason.getMessage());
    assertEquals(reason.getMessage(), "The account is expired.");

    assertNotNull(reason.toString());
    assertEquals(reason.toString(),
         "code=1\tname=account-not-usable\tmessage=The account is expired.");
  }



  /**
   * Tests the behavior for an account usability error without a message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutMessage()
         throws Exception
  {
    AuthenticationFailureReason reason = new AuthenticationFailureReason(
         AuthenticationFailureReason.FAILURE_TYPE_INVALID_CREDENTIALS,
         AuthenticationFailureReason.FAILURE_NAME_INVALID_CREDENTIALS,
         null);

    assertNotNull(reason.toString());
    assertEquals(reason.toString(),
         "code=9\tname=invalid-credentials");

    reason = new AuthenticationFailureReason(reason.toString());

    assertEquals(reason.getIntValue(),
         AuthenticationFailureReason.FAILURE_TYPE_INVALID_CREDENTIALS);

    assertNotNull(reason.getName());
    assertEquals(reason.getName(),
         AuthenticationFailureReason.FAILURE_NAME_INVALID_CREDENTIALS);

    assertNull(reason.getMessage());

    assertNotNull(reason.toString());
    assertEquals(reason.toString(),
         "code=9\tname=invalid-credentials");
  }



  /**
   * Tests the behavior when trying to decode a malformed string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedString()
         throws Exception
  {
    new AuthenticationFailureReason("malformed");
  }



  /**
   * Tests the behavior when trying to decode a string that doesn't have the
   * numeric code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMissingCode()
         throws Exception
  {
    new AuthenticationFailureReason(
         "name=incorrect-password\tmessage=The password was incorrect.");
  }



  /**
   * Tests the behavior when trying to decode a string that doesn't have the
   * name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMissingName()
         throws Exception
  {
    new AuthenticationFailureReason(
         "code=6\tmessage=The password was incorrect.");
  }
}
