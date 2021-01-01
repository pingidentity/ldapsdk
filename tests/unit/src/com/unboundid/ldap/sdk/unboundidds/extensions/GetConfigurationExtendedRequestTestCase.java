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
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the get configuration extended
 * request.
 */
public final class GetConfigurationExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when trying to create a request to retrieve the active
   * configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetActiveConfigurationRequest()
         throws Exception
  {
    GetConfigurationExtendedRequest r =
         GetConfigurationExtendedRequest.createGetActiveConfigurationRequest();
    assertNotNull(r);

    r = new GetConfigurationExtendedRequest(r);
    assertNotNull(r);

    r = r.duplicate();
    assertNotNull(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.28");

    assertNotNull(r.getValue());

    assertNotNull(r.getConfigurationType());
    assertEquals(r.getConfigurationType(), GetConfigurationType.ACTIVE);

    assertNull(r.getFileName());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to create a request to retrieve the baseline
   * configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetBaselineConfigurationRequest()
         throws Exception
  {
    GetConfigurationExtendedRequest r = GetConfigurationExtendedRequest.
         createGetBaselineConfigurationRequest("config.ldif.1234");
    assertNotNull(r);

    r = new GetConfigurationExtendedRequest(r);
    assertNotNull(r);

    r = r.duplicate();
    assertNotNull(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.28");

    assertNotNull(r.getValue());

    assertNotNull(r.getConfigurationType());
    assertEquals(r.getConfigurationType(), GetConfigurationType.BASELINE);

    assertNotNull(r.getFileName());
    assertEquals(r.getFileName(), "config.ldif.1234");

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to create a request to retrieve an archived
   * configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetArchivedConfigurationRequest()
         throws Exception
  {
    GetConfigurationExtendedRequest r =
         GetConfigurationExtendedRequest.createGetArchivedConfigurationRequest(
              "config-20130101000000Z", new Control("1.2.3.4"),
              new Control("1.2.3.5"));
    assertNotNull(r);

    r = new GetConfigurationExtendedRequest(r);
    assertNotNull(r);

    r = r.duplicate();
    assertNotNull(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.28");

    assertNotNull(r.getValue());

    assertNotNull(r.getConfigurationType());
    assertEquals(r.getConfigurationType(), GetConfigurationType.ARCHIVED);

    assertNotNull(r.getFileName());
    assertEquals(r.getFileName(), "config-20130101000000Z");

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode an extended request that does not
   * have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeWithoutValue()
         throws Exception
  {
    new GetConfigurationExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.28"));
  }



  /**
   * Tests the behavior when trying to decode an extended request whose value
   * cannot be parsed as an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new GetConfigurationExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.28", new ASN1OctetString("foo")));
  }



  /**
   * Tests the behavior when trying to decode an extended request whose value
   * sequence contains an invalid configuration type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidConfigType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x8F, "foo"));

    new GetConfigurationExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.28",
         new ASN1OctetString(valueSequence.encode())));
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
         GetConfigurationExtendedRequest.createGetActiveConfigurationRequest());
    assertResultCodeNot(result, ResultCode.SUCCESS);
    assertTrue(result instanceof GetConfigurationExtendedResult);

    conn.close();
  }
}
