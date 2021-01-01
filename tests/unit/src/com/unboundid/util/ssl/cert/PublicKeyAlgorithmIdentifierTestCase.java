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
 * This class provides test coverage for the PublicKeyAlgorithmIdentifier class.
 */
public class PublicKeyAlgorithmIdentifierTestCase
       extends LDAPSDKTestCase
{
  /**
   * Performs a number of tests for the defined set of values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValues()
         throws Exception
  {
    for (final PublicKeyAlgorithmIdentifier id :
         PublicKeyAlgorithmIdentifier.values())
    {
      assertNotNull(id);

      assertNotNull(id.getOID());

      assertNotNull(id.getName());

      assertNotNull(PublicKeyAlgorithmIdentifier.forOID(id.getOID()));
      assertEquals(PublicKeyAlgorithmIdentifier.forOID(id.getOID()), id);

      assertNotNull(PublicKeyAlgorithmIdentifier.getNameOrOID(id.getOID()));
      assertEquals(PublicKeyAlgorithmIdentifier.getNameOrOID(id.getOID()),
           id.getName());

      assertNotNull(PublicKeyAlgorithmIdentifier.valueOf(id.name()));
      assertEquals(PublicKeyAlgorithmIdentifier.valueOf(id.name()), id);
    }
  }



  /**
   * Tests the behavior when attempting to use a nonexistent value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonexistentValue()
         throws Exception
  {
    assertNull(PublicKeyAlgorithmIdentifier.forOID(new OID("1.2.3.4")));

    assertNotNull(PublicKeyAlgorithmIdentifier.getNameOrOID(
         new OID("1.2.3.4")));
    assertEquals(PublicKeyAlgorithmIdentifier.getNameOrOID(new OID("1.2.3.4")),
         "1.2.3.4");

    try
    {
      PublicKeyAlgorithmIdentifier.valueOf("nonexistent");
      fail("Expected an exception from valueOf with a nonexistent name");
    }
    catch (final IllegalArgumentException iae)
    {
      // This was expected.
    }
  }
}
