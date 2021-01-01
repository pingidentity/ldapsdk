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
 * account usability notice class.
 */
public final class PasswordPolicyStateAccountUsabilityNoticeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for an account usability notice with a message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithMessage()
         throws Exception
  {
    PasswordPolicyStateAccountUsabilityNotice notice =
         new PasswordPolicyStateAccountUsabilityNotice(
              PasswordPolicyStateAccountUsabilityNotice.
                   NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
              PasswordPolicyStateAccountUsabilityNotice.
                   NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
              "The user has an outstanding retired password");

    assertNotNull(notice.toString());
    assertEquals(notice.toString(),
         "code=1\tname=outstanding-retired-password\tmessage=The user has an " +
              "outstanding retired password");

    notice =
         new PasswordPolicyStateAccountUsabilityNotice(notice.toString());

    assertEquals(notice.getIntValue(),
         PasswordPolicyStateAccountUsabilityNotice.
              NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD);

    assertNotNull(notice.getName());
    assertEquals(notice.getName(),
         PasswordPolicyStateAccountUsabilityNotice.
              NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD);

    assertNotNull(notice.getMessage());
    assertEquals(notice.getMessage(),
         "The user has an outstanding retired password");

    assertNotNull(notice.toString());
    assertEquals(notice.toString(),
         "code=1\tname=outstanding-retired-password\tmessage=The user has an " +
              "outstanding retired password");
  }



  /**
   * Tests the behavior for an account usability notice without a message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutMessage()
         throws Exception
  {
    PasswordPolicyStateAccountUsabilityNotice notice =
         new PasswordPolicyStateAccountUsabilityNotice(
              PasswordPolicyStateAccountUsabilityNotice.
                   NOTICE_TYPE_OUTSTANDING_ONE_TIME_PASSWORD,
              PasswordPolicyStateAccountUsabilityNotice.
                   NOTICE_NAME_OUTSTANDING_ONE_TIME_PASSWORD,
              null);

    assertNotNull(notice.toString());
    assertEquals(notice.toString(),
         "code=2\tname=outstanding-one-time-password");

    notice =
         new PasswordPolicyStateAccountUsabilityNotice(notice.toString());

    assertEquals(notice.getIntValue(),
         PasswordPolicyStateAccountUsabilityNotice.
              NOTICE_TYPE_OUTSTANDING_ONE_TIME_PASSWORD);

    assertNotNull(notice.getName());
    assertEquals(notice.getName(),
         PasswordPolicyStateAccountUsabilityNotice.
              NOTICE_NAME_OUTSTANDING_ONE_TIME_PASSWORD);

    assertNull(notice.getMessage());

    assertNotNull(notice.toString());
    assertEquals(notice.toString(),
         "code=2\tname=outstanding-one-time-password");
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
    new PasswordPolicyStateAccountUsabilityNotice("malformed");
  }



  /**
   * Tests the behavior when trying to decode a string that doesn't have the
   * notice code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMissingCode()
         throws Exception
  {
    new PasswordPolicyStateAccountUsabilityNotice(
         "name=notice-type\tmessage=This is the message");
  }



  /**
   * Tests the behavior when trying to decode a string that doesn't have the
   * notice name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMissingName()
         throws Exception
  {
    new PasswordPolicyStateAccountUsabilityNotice(
         "code=1\tmessage=This is the message");
  }
}
