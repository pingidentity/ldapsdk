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

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.OID;



/**
 * This class provides a set of test cases for the BasicConstraintsExtension
 * class.
 */
public final class BasicConstraintsExtensionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests an extension that is not a CA and does not have a path length
   * constraint.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNotCANoPathLengthConstraint()
         throws Exception
  {
    BasicConstraintsExtension e =
         new BasicConstraintsExtension(true, false, null);

    e = new BasicConstraintsExtension(e);

    assertNotNull(e.getOID());
    assertEquals(e.getOID().toString(), "2.5.29.19");

    assertTrue(e.isCritical());

    assertNotNull(e.getValue());

    assertFalse(e.isCA());

    assertNull(e.getPathLengthConstraint());

    assertNotNull(e.getExtensionName());
    assertFalse(e.getExtensionName().equals("2.5.29.19"));

    assertNotNull(e.toString());
  }



  /**
   * Tests an extension that is a CA and has a path length constraint.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsCAWithPathLengthConstraint()
         throws Exception
  {
    BasicConstraintsExtension e =
         new BasicConstraintsExtension(false, true, 5);

    e = new BasicConstraintsExtension(e);

    assertNotNull(e.getOID());
    assertEquals(e.getOID().toString(), "2.5.29.19");

    assertFalse(e.isCritical());

    assertNotNull(e.getValue());

    assertTrue(e.isCA());

    assertNotNull(e.getPathLengthConstraint());
    assertEquals(e.getPathLengthConstraint().intValue(), 5);

    assertNotNull(e.getExtensionName());
    assertFalse(e.getExtensionName().equals("2.5.29.19"));

    assertNotNull(e.toString());
  }



  /**
   * Tests the behavior when trying to decode a generic extension that cannot be
   * decoded as a basic constraints extension.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedExtension()
         throws Exception
  {
    final X509CertificateExtension e =
         new X509CertificateExtension(new OID("2.5.29.19"), false,
              "malformed value".getBytes("UTF-8"));
    new BasicConstraintsExtension(e);
  }
}
