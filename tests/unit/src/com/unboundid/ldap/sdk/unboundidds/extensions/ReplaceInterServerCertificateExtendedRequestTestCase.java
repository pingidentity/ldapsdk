/*
 * Copyright 2021-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021-2025 Ping Identity Corporation
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
 * Copyright (C) 2021-2025 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the
 * {@code ReplaceInterServerCertificateExtendedRequest} class.
 */
public final class ReplaceInterServerCertificateExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a valid request that does not include any controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequestWithoutControls()
         throws Exception
  {
    ReplaceInterServerCertificateExtendedRequest r =
         new ReplaceInterServerCertificateExtendedRequest(
              new KeyStoreFileReplaceCertificateKeyStoreContent("test-file",
                   "test-pin", null, null, null),
              false);

    r = new ReplaceInterServerCertificateExtendedRequest(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.69");

    assertNotNull(r.getKeyStoreContent());
    assertTrue(r.getKeyStoreContent() instanceof
         KeyStoreFileReplaceCertificateKeyStoreContent);

    assertFalse(r.skipCertificateValidation());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior for a valid request that includes controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequestWithControls()
         throws Exception
  {
    ReplaceInterServerCertificateExtendedRequest r =
         new ReplaceInterServerCertificateExtendedRequest(
              new KeyStoreFileReplaceCertificateKeyStoreContent("test-file",
                   "test-pin", null, null, null),
              true,
              new Control("1.2.3.4"),
              new Control("1.2.3.5", true, new ASN1OctetString("foo")));

    r = new ReplaceInterServerCertificateExtendedRequest(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.69");

    assertNotNull(r.getKeyStoreContent());
    assertTrue(r.getKeyStoreContent() instanceof
         KeyStoreFileReplaceCertificateKeyStoreContent);

    assertTrue(r.skipCertificateValidation());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode an extended request that has the
   * right OID but no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeRequestMissingValue()
         throws Exception
  {
    try
    {
      new ReplaceInterServerCertificateExtendedRequest(new ExtendedRequest(
           "1.3.6.1.4.1.30221.2.6.69"));
      fail("Expected an exception when trying to decode a request with no " +
           "value");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to decode an extended request that has the
   * right OID but a malformed value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeRequestMalformedValue()
         throws Exception
  {
    try
    {
      new ReplaceInterServerCertificateExtendedRequest(new ExtendedRequest(
           "1.3.6.1.4.1.30221.2.6.69", new ASN1OctetString("malformed")));
      fail("Expected an exception when trying to decode a request with a " +
           "malformed value");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
  }
}
