/*
 * Copyright 2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2025 Ping Identity Corporation
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
 * Copyright (C) 2025 Ping Identity Corporation
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



import java.util.UUID;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for transaction settings scoped lock
 * details.
 */
public final class TransactionSettingsScopedLockDetailsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for settings that includes a lock timeout.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDetails()
         throws Exception
  {
    final String scopeID = UUID.randomUUID().toString();
    TransactionSettingsScopedLockDetails details =
         new TransactionSettingsScopedLockDetails(scopeID,
              TransactionSettingsBackendLockBehavior.ACQUIRE_BEFORE_RETRIES);

    details = TransactionSettingsScopedLockDetails.decode(details.encode());

    assertNotNull(details);

    assertNotNull(details.getScopeIdentifier());
    assertEquals(details.getScopeIdentifier(), scopeID);

    assertNotNull(details.getLockBehavior());
    assertEquals(details.getLockBehavior(),
         TransactionSettingsBackendLockBehavior.ACQUIRE_BEFORE_RETRIES);

    assertNotNull(details.toString());
  }



  /**
   * Tests the behavior for settings that indicate that the server should not
   * actually attempt to acquire the lock.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoNotAcquire()
         throws Exception
  {
    final String scopeID = UUID.randomUUID().toString();
    TransactionSettingsScopedLockDetails details =
         new TransactionSettingsScopedLockDetails(scopeID,
              TransactionSettingsBackendLockBehavior.DO_NOT_ACQUIRE);

    assertNotNull(details.getScopeIdentifier());
    assertEquals(details.getScopeIdentifier(), scopeID);

    assertNotNull(details.getLockBehavior());
    assertEquals(details.getLockBehavior(),
         TransactionSettingsBackendLockBehavior.DO_NOT_ACQUIRE);

    assertNull(details.encode());

    assertNotNull(details.toString());
  }



  /**
   * Verifies that the SDK will not report an error when attempting to decode a
   * null element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeNullElement()
         throws Exception
  {
    assertNull(TransactionSettingsScopedLockDetails.decode(null));
  }



  /**
   * Tests the behavior when trying to decode an element that does not represent
   * a valid scoped lock details encoding.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeMalformedElement()
         throws Exception
  {
    try
    {
      TransactionSettingsScopedLockDetails.decode(
           new ASN1OctetString("not-a-valid-encoded-set-of-details"));
      fail("Expected an exception when trying to decode a malformed scoped " +
           "lock details element.");
    }
    catch (final LDAPException e)
    {
      // This was expected.
      assertEquals(e.getResultCode(), ResultCode.PROTOCOL_ERROR);
    }
  }
}
