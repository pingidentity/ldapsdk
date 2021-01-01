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
package com.unboundid.ldap.sdk.unboundidds.controls;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code JoinBaseDN} class.
 */
public class JoinBaseDNTestCase
       extends LDAPSDKTestCase
{
  /**
   * Performs a set of tests involving the "useSearchBaseDN" type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUseSearchBaseDN()
         throws Exception
  {
    JoinBaseDN baseDN = JoinBaseDN.createUseSearchBaseDN();
    baseDN = JoinBaseDN.decode(baseDN.encode());
    assertNotNull(baseDN);

    assertEquals(baseDN.getType(), JoinBaseDN.BASE_TYPE_SEARCH_BASE);

    assertNull(baseDN.getCustomBaseDN());

    assertNotNull(baseDN.toString());
  }



  /**
   * Performs a set of tests involving the "useSourceEntryDN" type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUseSourceEntryDN()
         throws Exception
  {
    JoinBaseDN baseDN = JoinBaseDN.createUseSourceEntryDN();
    baseDN = JoinBaseDN.decode(baseDN.encode());
    assertNotNull(baseDN);

    assertEquals(baseDN.getType(), JoinBaseDN.BASE_TYPE_SOURCE_ENTRY_DN);

    assertNull(baseDN.getCustomBaseDN());

    assertNotNull(baseDN.toString());
  }



  /**
   * Performs a set of tests involving the "useCustomBaseDN" type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUseCustomBaseDN()
         throws Exception
  {
    JoinBaseDN baseDN = JoinBaseDN.createUseCustomBaseDN("dc=example,dc=com");
    baseDN = JoinBaseDN.decode(baseDN.encode());
    assertNotNull(baseDN);

    assertEquals(baseDN.getType(), JoinBaseDN.BASE_TYPE_CUSTOM);

    assertNotNull(baseDN.getCustomBaseDN());
    assertEquals(new DN(baseDN.getCustomBaseDN()),
                 new DN("dc=example,dc=com"));

    assertNotNull(baseDN.toString());
  }



  /**
   * Tests the {@code decode} method with an element containing an invalid
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidType()
         throws Exception
  {
    JoinBaseDN.decode(new ASN1Element((byte) 0x00));
  }
}
