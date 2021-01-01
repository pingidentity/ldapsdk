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
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.asn1.ASN1OctetString;



/**
 * This class provides test coverage for the {@code LDAPExtendedResponse} class.
 */
public class LDAPExtendedResponseTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests with an extended result that does not have an OID or value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutOIDOrValue()
         throws Exception
  {
    LDAPExtendedResponse r = new LDAPExtendedResponse(new ExtendedResult(
         1, ResultCode.SUCCESS, null, null, null, null, null, null));

    assertNotNull(r);

    assertEquals(r.getMessageID(), 1);

    assertEquals(r.getResultCode(), ResultCode.SUCCESS_INT_VALUE);

    assertNull(r.getErrorMessage());

    assertNull(r.getMatchedDN());

    assertNull(r.getReferrals());

    assertNull(r.getControls());

    assertNotNull(r.toLDAPResult());

    assertNull(r.getID());

    assertNull(r.getValue());

    assertNotNull(r.toExtendedResult());

    assertNotNull(r.toString());
  }



  /**
   * Tests with an extended result that has both an OID and a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutOIDAndValue()
         throws Exception
  {
    String[] refs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server2.example.com/dc=example,dc=com",
    };

    Control[] controls =
    {
      new Control("1.2.3.5", true),
      new Control("1.2.3.6", false, new ASN1OctetString())
    };

    LDAPExtendedResponse r = new LDAPExtendedResponse(new ExtendedResult(
         2, ResultCode.NO_SUCH_OBJECT, "doesn't exist", "dc=example,dc=com",
         refs, "1.2.3.4", new ASN1OctetString("foo"), controls));

    assertNotNull(r);

    assertEquals(r.getMessageID(), 2);

    assertEquals(r.getResultCode(), ResultCode.NO_SUCH_OBJECT_INT_VALUE);

    assertNotNull(r.getErrorMessage());
    assertEquals(r.getErrorMessage(), "doesn't exist");

    assertNotNull(r.getMatchedDN());
    assertEquals(r.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(r.getReferrals());
    assertEquals(r.getReferrals().length, 2);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.toLDAPResult());

    assertNotNull(r.getID());
    assertEquals(r.getID(), "1.2.3.4");

    assertNotNull(r.getValue());

    assertNotNull(r.toExtendedResult());

    assertNotNull(r.toString());
  }
}
