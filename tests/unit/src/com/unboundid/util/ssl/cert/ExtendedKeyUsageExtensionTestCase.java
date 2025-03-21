/*
 * Copyright 2017-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2025 Ping Identity Corporation
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
 * Copyright (C) 2017-2025 Ping Identity Corporation
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
package com.unboundid.util.ssl.cert;



import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.OID;



/**
 * This class provides a set of test cases for the ExtendedKeyUsageExtension
 * class.
 */
public final class ExtendedKeyUsageExtensionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests with an extension that has a single usage ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithSingleUsageID()
         throws Exception
  {
    ExtendedKeyUsageExtension e = new ExtendedKeyUsageExtension(false,
         Collections.singletonList(ExtendedKeyUsageID.
              TLS_SERVER_AUTHENTICATION.getOID()));

    e = new ExtendedKeyUsageExtension(e);

    assertNotNull(e.getOID());
    assertEquals(e.getOID().toString(), "2.5.29.37");

    assertFalse(e.isCritical());

    assertNotNull(e.getValue());

    assertNotNull(e.getKeyPurposeIDs());
    assertEquals(e.getKeyPurposeIDs().size(), 1);
    assertEquals(e.getKeyPurposeIDs().iterator().next(),
         ExtendedKeyUsageID.TLS_SERVER_AUTHENTICATION.getOID());

    assertNotNull(e.getExtensionName());
    assertFalse(e.getExtensionName().equals("2.5.29.37"));

    assertNotNull(e.toString());
  }



  /**
   * Tests with an extension that has multiple usage IDs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithMultipleUsageIDs()
         throws Exception
  {
    ExtendedKeyUsageExtension e = new ExtendedKeyUsageExtension(true,
         Arrays.asList(
              ExtendedKeyUsageID.TLS_SERVER_AUTHENTICATION.getOID(),
              ExtendedKeyUsageID.TLS_CLIENT_AUTHENTICATION.getOID(),
              ExtendedKeyUsageID.CODE_SIGNING.getOID(),
              ExtendedKeyUsageID.EMAIL_PROTECTION.getOID()));

    e = new ExtendedKeyUsageExtension(e);

    assertNotNull(e.getOID());
    assertEquals(e.getOID().toString(), "2.5.29.37");

    assertTrue(e.isCritical());

    assertNotNull(e.getValue());

    assertNotNull(e.getKeyPurposeIDs());
    assertEquals(e.getKeyPurposeIDs().size(), 4);

    final Iterator<OID> iterator = e.getKeyPurposeIDs().iterator();
    assertEquals(iterator.next(),
         ExtendedKeyUsageID.TLS_SERVER_AUTHENTICATION.getOID());
    assertEquals(iterator.next(),
         ExtendedKeyUsageID.TLS_CLIENT_AUTHENTICATION.getOID());
    assertEquals(iterator.next(), ExtendedKeyUsageID.CODE_SIGNING.getOID());
    assertEquals(iterator.next(), ExtendedKeyUsageID.EMAIL_PROTECTION.getOID());
    assertFalse(iterator.hasNext());

    assertNotNull(e.getExtensionName());
    assertFalse(e.getExtensionName().equals("2.5.29.37"));

    assertNotNull(e.toString());
  }



  /**
   * Tests the behavior when trying to create an extension with an invalid OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testCreateWithInvalidOID()
         throws Exception
  {
    new ExtendedKeyUsageExtension(false,
         Collections.singletonList(new OID("1234.5678")));
  }



  /**
   * Tests the behavior when trying to decode an extension that cannot be
   * decoded as an extended key usage extension.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedExtension()
         throws Exception
  {
    new ExtendedKeyUsageExtension(new X509CertificateExtension(
         new OID("2.5.29.37"), false, "invalid value".getBytes("UTF-8")));
  }
}
