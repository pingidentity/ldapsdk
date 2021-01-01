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
 * account usability warning class.
 */
public final class PasswordPolicyStateAccountUsabilityWarningTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for an account usability warning with a message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithMessage()
         throws Exception
  {
    PasswordPolicyStateAccountUsabilityWarning warning =
         new PasswordPolicyStateAccountUsabilityWarning(
              PasswordPolicyStateAccountUsabilityWarning.
                   WARNING_TYPE_ACCOUNT_EXPIRING,
              PasswordPolicyStateAccountUsabilityWarning.
                   WARNING_NAME_ACCOUNT_EXPIRING,
              "The account will expire soon");

    assertNotNull(warning.toString());
    assertEquals(warning.toString(),
         "code=1\tname=account-expiring\tmessage=The account will expire soon");

    warning =
         new PasswordPolicyStateAccountUsabilityWarning(warning.toString());

    assertEquals(warning.getIntValue(),
         PasswordPolicyStateAccountUsabilityWarning.
              WARNING_TYPE_ACCOUNT_EXPIRING);

    assertNotNull(warning.getName());
    assertEquals(warning.getName(),
         PasswordPolicyStateAccountUsabilityWarning.
              WARNING_NAME_ACCOUNT_EXPIRING);

    assertNotNull(warning.getMessage());
    assertEquals(warning.getMessage(), "The account will expire soon");

    assertNotNull(warning.toString());
    assertEquals(warning.toString(),
         "code=1\tname=account-expiring\tmessage=The account will expire soon");
  }



  /**
   * Tests the behavior for an account usability warning without a message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutMessage()
         throws Exception
  {
    PasswordPolicyStateAccountUsabilityWarning warning =
         new PasswordPolicyStateAccountUsabilityWarning(
              PasswordPolicyStateAccountUsabilityWarning.
                   WARNING_TYPE_PASSWORD_EXPIRING,
              PasswordPolicyStateAccountUsabilityWarning.
                   WARNING_NAME_PASSWORD_EXPIRING,
              null);

    assertNotNull(warning.toString());
    assertEquals(warning.toString(),
         "code=2\tname=password-expiring");

    warning =
         new PasswordPolicyStateAccountUsabilityWarning(warning.toString());

    assertEquals(warning.getIntValue(),
         PasswordPolicyStateAccountUsabilityWarning.
              WARNING_TYPE_PASSWORD_EXPIRING);

    assertNotNull(warning.getName());
    assertEquals(warning.getName(),
         PasswordPolicyStateAccountUsabilityWarning.
              WARNING_NAME_PASSWORD_EXPIRING);

    assertNull(warning.getMessage());

    assertNotNull(warning.toString());
    assertEquals(warning.toString(),
         "code=2\tname=password-expiring");
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
    new PasswordPolicyStateAccountUsabilityWarning("malformed");
  }



  /**
   * Tests the behavior when trying to decode a string that doesn't have the
   * warning code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMissingCode()
         throws Exception
  {
    new PasswordPolicyStateAccountUsabilityWarning(
         "name=account-expiring\tmessage=The account will expire soon");
  }



  /**
   * Tests the behavior when trying to decode a string that doesn't have the
   * warning name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMissingName()
         throws Exception
  {
    new PasswordPolicyStateAccountUsabilityWarning(
         "code=1\tmessage=The account will expire soon");
  }
}
