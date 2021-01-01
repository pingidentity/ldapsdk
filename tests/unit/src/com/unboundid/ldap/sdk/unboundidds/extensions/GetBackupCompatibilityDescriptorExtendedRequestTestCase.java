/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the get backup compatibility
 * descriptor extended request.
 */
public final class GetBackupCompatibilityDescriptorExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a valid request without controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidRequestWithoutControls()
         throws Exception
  {
    GetBackupCompatibilityDescriptorExtendedRequest r =
         new GetBackupCompatibilityDescriptorExtendedRequest(
              "dc=example,dc=com");

    r = new GetBackupCompatibilityDescriptorExtendedRequest(r);
    assertNotNull(r);

    r = r.duplicate();
    assertNotNull(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.30");

    assertNotNull(r.getValue());

    assertNotNull(r.getBaseDN());
    assertDNsEqual(r.getBaseDN(), "dc=example,dc=com");

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior for a valid request with controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidRequestWithControls()
         throws Exception
  {
    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5")
    };

    GetBackupCompatibilityDescriptorExtendedRequest r =
         new GetBackupCompatibilityDescriptorExtendedRequest("o=example.com",
              controls);

    r = new GetBackupCompatibilityDescriptorExtendedRequest(r);
    assertNotNull(r);

    r = r.duplicate();
    assertNotNull(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.30");

    assertNotNull(r.getValue());

    assertNotNull(r.getBaseDN());
    assertDNsEqual(r.getBaseDN(), "o=example.com");

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when attempting to decode an extended request that does
   * not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeWithoutValue()
         throws Exception
  {
    final ExtendedRequest r = new ExtendedRequest("1.3.6.1.4.1.30221.2.6.30");
    new GetBackupCompatibilityDescriptorExtendedRequest(r);
  }



  /**
   * Tests the behavior when attempting to decode an extended request whose
   * value is not a valid ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    final ExtendedRequest r = new ExtendedRequest("1.3.6.1.4.1.30221.2.6.30",
         new ASN1OctetString("foo"));
    new GetBackupCompatibilityDescriptorExtendedRequest(r);
  }



  /**
   * Provides test coverage for the process method.  It won't be successful
   * because the in-memory directory server doesn't support this operation,
   * but at least it will provide test coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcess()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    final ExtendedResult result = conn.processExtendedOperation(
         new GetBackupCompatibilityDescriptorExtendedRequest(
              "dc=example,dc=com"));
    assertResultCodeNot(result, ResultCode.SUCCESS);
    assertTrue(result instanceof
         GetBackupCompatibilityDescriptorExtendedResult);

    conn.close();
  }
}
