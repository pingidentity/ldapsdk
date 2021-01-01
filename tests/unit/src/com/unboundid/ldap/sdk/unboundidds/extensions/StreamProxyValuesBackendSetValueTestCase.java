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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the
 * {@code StreamProxyValuesBackendSetValue} class.
 */
public class StreamProxyValuesBackendSetValueTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for this class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasic()
         throws Exception
  {
    StreamProxyValuesBackendSetValue v =
         new StreamProxyValuesBackendSetValue(new ASN1OctetString("foo"),
                                              new ASN1OctetString("bar"));
    v = StreamProxyValuesBackendSetValue.decode(v.encode());

    assertNotNull(v);

    assertNotNull(v.getBackendSetID());
    assertEquals(v.getBackendSetID().stringValue(), "foo");

    assertNotNull(v.getValue());
    assertEquals(v.getValue().stringValue(), "bar");

    assertNotNull(v.toString());
  }



  /**
   * Verifies that it is not possible to create a backend set value with a
   * {@code null} backend set ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullBackendSetID()
         throws Exception
  {
    new StreamProxyValuesBackendSetValue(null, new ASN1OctetString("bar"));
  }



  /**
   * Verifies that it is not possible to create a backend set value with a
   * {@code null} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullValue()
         throws Exception
  {
    new StreamProxyValuesBackendSetValue(new ASN1OctetString("foo"), null);
  }



  /**
   * Tests the behavior when attempting to decode an invalid element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalid()
         throws Exception
  {
    StreamProxyValuesBackendSetValue.decode(new ASN1OctetString("foo"));
  }
}
