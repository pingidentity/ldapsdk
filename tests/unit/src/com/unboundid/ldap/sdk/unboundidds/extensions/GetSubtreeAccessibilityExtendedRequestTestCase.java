/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the get subtree accessibility
 * extended request.
 */
public final class GetSubtreeAccessibilityExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides a basic set of tests for the get subtree accessibility request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAccessibilityRequest()
         throws Exception
  {
    GetSubtreeAccessibilityExtendedRequest r =
         new GetSubtreeAccessibilityExtendedRequest(
              new Control("1.2.3.4"), new Control("1.2.3.5"));
    r = new GetSubtreeAccessibilityExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode an extended request with a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeWithValue()
         throws Exception
  {
    new GetSubtreeAccessibilityExtendedRequest(new ExtendedRequest(
         GetSubtreeAccessibilityExtendedRequest.
              GET_SUBTREE_ACCESSIBILITY_REQUEST_OID,
         new ASN1OctetString("foo")));
  }



  /**
   * Provides test coverage for the process method.  The in-memory server
   * won't be able to actually process the request, but it'll at least provide
   * us with coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcess()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    final GetSubtreeAccessibilityExtendedResult r =
         (GetSubtreeAccessibilityExtendedResult)
         conn.processExtendedOperation(
              new GetSubtreeAccessibilityExtendedRequest());

    assertNotNull(r);

    assertResultCodeNot(r, ResultCode.SUCCESS);

    assertNull(r.getAccessibilityRestrictions());

    assertNotNull(r.toString());

    conn.close();
  }
}
