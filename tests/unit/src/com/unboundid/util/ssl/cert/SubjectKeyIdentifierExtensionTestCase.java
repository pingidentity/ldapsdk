/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.OID;
import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for the SubjectKeyIdentifierExtension
 * class.
 */
public class SubjectKeyIdentifierExtensionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with a valid extension.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidExtension()
         throws Exception
  {
    final ASN1OctetString value = new ASN1OctetString("foo");
    SubjectKeyIdentifierExtension skie =
         new SubjectKeyIdentifierExtension(false, value);

    skie = new SubjectKeyIdentifierExtension(skie);

    assertNotNull(skie.getOID());
    assertEquals(skie.getOID(), new OID("2.5.29.14"));

    assertFalse(skie.isCritical());

    assertNotNull(skie.getValue());
    assertEquals(skie.getValue(), value.encode());

    assertNotNull(skie.getKeyIdentifier());
    assertEquals(skie.getKeyIdentifier(), value);

    assertNotNull(skie.getExtensionName());

    assertNotNull(skie.toString());
  }



  /**
   * Tests the behavior with an extension whose value cannot be parsed as an
   * ASN.1 octet string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testExtensionValueNotOctetString()
         throws Exception
  {
    final X509CertificateExtension genericExtension =
         new X509CertificateExtension(new OID("2.5.29.14"), false,
              StaticUtils.NO_BYTES);
    new SubjectKeyIdentifierExtension(genericExtension);
  }
}
