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



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the {@code LDAPExtendedOperation}
 * class.
 */
public class LDAPExtendedOperationTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when creating an extended operation with an OID but no
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithOIDAndNoValue()
         throws Exception
  {
    LDAPExtendedOperation o = new LDAPExtendedOperation("1.2.3.4", null);

    assertNotNull(o);

    assertNotNull(o.getID());
    assertEquals(o.getID(), "1.2.3.4");

    assertNull(o.getValue());

    assertNotNull(o.toExtendedRequest());

    assertNotNull(o.toString());
  }



  /**
   * Tests the behavior when creating an extended operation with an OID and a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithOIDAndValue()
         throws Exception
  {
    LDAPExtendedOperation o =
         new LDAPExtendedOperation("1.2.3.4", "foo".getBytes());

    assertNotNull(o);

    assertNotNull(o.getID());
    assertEquals(o.getID(), "1.2.3.4");

    assertNotNull(o.getValue());
    assertTrue(Arrays.equals(o.getValue(), "foo".getBytes()));

    assertNotNull(o.toExtendedRequest());

    assertNotNull(o.toString());
  }



  /**
   * Tests the behavior when creating an extended operation from an SDK extended
   * request with an OID but no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateFromExtendedRequestWithOIDAndNoValue()
         throws Exception
  {
    LDAPExtendedOperation o =
         new LDAPExtendedOperation(new ExtendedRequest("1.2.3.4"));

    assertNotNull(o);

    assertNotNull(o.getID());
    assertEquals(o.getID(), "1.2.3.4");

    assertNull(o.getValue());

    assertNotNull(o.toExtendedRequest());

    assertNotNull(o.toString());
  }



  /**
   * Tests the behavior when creating an extended operation from an SDK extended
   * request with an OID and a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateFromExtendedRequestWithOIDAndValue()
         throws Exception
  {
    LDAPExtendedOperation o = new LDAPExtendedOperation(
         new ExtendedRequest("1.2.3.4", new ASN1OctetString("foo")));

    assertNotNull(o);

    assertNotNull(o.getID());
    assertEquals(o.getID(), "1.2.3.4");

    assertNotNull(o.getValue());
    assertTrue(Arrays.equals(o.getValue(), "foo".getBytes()));

    assertNotNull(o.toExtendedRequest());

    assertNotNull(o.toString());
  }
}
