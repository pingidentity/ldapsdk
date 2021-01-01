/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the SRVRecord class.
 */
public final class SRVRecordTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the ability to decode a valid SRV record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValidRecord()
         throws Exception
  {
    final SRVRecord r = new SRVRecord("1 2 389 ldap.example.com");

    assertNotNull(r);

    assertNotNull(r.getAddress());
    assertEquals(r.getAddress(), "ldap.example.com");

    assertEquals(r.getPort(), 389);

    assertEquals(r.getPriority(), 1);

    assertEquals(r.getWeight(), 2);

    assertNotNull(r.toString());
  }



  /**
   * Tests the ability to decode a valid SRV record with a trailing period after
   * the address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValidRecordWithTrailingPeriod()
         throws Exception
  {
    final SRVRecord r = new SRVRecord("4 5 1389 ds.example.com.");

    assertNotNull(r);

    assertNotNull(r.getAddress());
    assertEquals(r.getAddress(), "ds.example.com");

    assertEquals(r.getPort(), 1389);

    assertEquals(r.getPriority(), 4);

    assertEquals(r.getWeight(), 5);

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when attempting to interact with a malformed record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testMalformedRecord()
         throws Exception
  {
    new SRVRecord("malformed");
  }
}
