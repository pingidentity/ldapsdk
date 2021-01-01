/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the password policy state
 * account usability error class.
 */
public final class PasswordPolicyStateAccountUsabilityErrorTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for an account usability error with a message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithMessage()
         throws Exception
  {
    PasswordPolicyStateAccountUsabilityError error =
         new PasswordPolicyStateAccountUsabilityError(
              PasswordPolicyStateAccountUsabilityError.
                   ERROR_TYPE_ACCOUNT_EXPIRED,
              PasswordPolicyStateAccountUsabilityError.
                   ERROR_NAME_ACCOUNT_EXPIRED,
              "The account has expired");

    assertNotNull(error.toString());
    assertEquals(error.toString(),
         "code=3\tname=account-expired\tmessage=The account has expired");

    error = new PasswordPolicyStateAccountUsabilityError(error.toString());

    assertEquals(error.getIntValue(),
         PasswordPolicyStateAccountUsabilityError.ERROR_TYPE_ACCOUNT_EXPIRED);

    assertNotNull(error.getName());
    assertEquals(error.getName(),
         PasswordPolicyStateAccountUsabilityError.ERROR_NAME_ACCOUNT_EXPIRED);

    assertNotNull(error.getMessage());
    assertEquals(error.getMessage(), "The account has expired");

    assertNotNull(error.toString());
    assertEquals(error.toString(),
         "code=3\tname=account-expired\tmessage=The account has expired");
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
    PasswordPolicyStateAccountUsabilityError error =
         new PasswordPolicyStateAccountUsabilityError(
              PasswordPolicyStateAccountUsabilityError.
                   ERROR_TYPE_ACCOUNT_NOT_YET_ACTIVE,
              PasswordPolicyStateAccountUsabilityError.
                   ERROR_NAME_ACCOUNT_NOT_YET_ACTIVE,
              null);

    assertNotNull(error.toString());
    assertEquals(error.toString(),
         "code=2\tname=account-not-yet-active");

    error = new PasswordPolicyStateAccountUsabilityError(error.toString());

    assertEquals(error.getIntValue(),
         PasswordPolicyStateAccountUsabilityError.
              ERROR_TYPE_ACCOUNT_NOT_YET_ACTIVE);

    assertNotNull(error.getName());
    assertEquals(error.getName(),
         PasswordPolicyStateAccountUsabilityError.
              ERROR_NAME_ACCOUNT_NOT_YET_ACTIVE);

    assertNull(error.getMessage());

    assertNotNull(error.toString());
    assertEquals(error.toString(),
         "code=2\tname=account-not-yet-active");
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
    new PasswordPolicyStateAccountUsabilityError("malformed");
  }



  /**
   * Tests the behavior when trying to decode a string that doesn't have the
   * error code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMissingCode()
         throws Exception
  {
    new PasswordPolicyStateAccountUsabilityError(
         "name=account-expired\tmessage=The account has expired");
  }



  /**
   * Tests the behavior when trying to decode a string that doesn't have the
   * error name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMissingName()
         throws Exception
  {
    new PasswordPolicyStateAccountUsabilityError(
         "code=3\tmessage=The account has expired");
  }
}
