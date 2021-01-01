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

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides test coverage for the {@code LDAPResponse} class.
 */
public class LDAPResponseTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a success response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccess()
         throws Exception
  {
    LDAPResponse r = new LDAPResponse(new LDAPResult(1, ResultCode.SUCCESS));

    assertNotNull(r);

    assertEquals(r.getMessageID(), 1);

    assertEquals(r.getResultCode(), 0);

    assertNull(r.getErrorMessage());

    assertNull(r.getMatchedDN());

    assertNull(r.getReferrals());

    assertNull(r.getControls());

    assertNotNull(r.toLDAPResult());

    assertNotNull(r.toString());
  }



  /**
   * Tests a non-success response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonSuccess()
         throws Exception
  {
    String[] refs =
    {
      "ldap://server1.example.com:389/dc=example,dc=com",
      "ldap://server2.example.com:389/dc=example,dc=com"
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true),
    };

    LDAPResponse r = new LDAPResponse(new LDAPResult(2,
         ResultCode.NO_SUCH_OBJECT, "error message", "dc=example,dc=com", refs,
         controls));

    assertNotNull(r);

    assertEquals(r.getMessageID(), 2);

    assertEquals(r.getResultCode(), 32);

    assertNotNull(r.getErrorMessage());
    assertEquals(r.getErrorMessage(), "error message");

    assertNotNull(r.getMatchedDN());
    assertEquals(r.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(r.getReferrals());
    assertEquals(r.getReferrals().length, 2);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.toLDAPResult());

    assertNotNull(r.toString());
  }
}
