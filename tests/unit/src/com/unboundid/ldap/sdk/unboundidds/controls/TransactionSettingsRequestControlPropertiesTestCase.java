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



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for transaction settings request
 * control properties.
 */
public final class TransactionSettingsRequestControlPropertiesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a set of properties using all default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllDefaultValues()
         throws Exception
  {
    final TransactionSettingsReqeustControlProperties properties =
         new TransactionSettingsReqeustControlProperties();

    assertNull(properties.getTransactionName());

    assertNull(properties.getCommitDurability());

    assertNull(properties.getBackendExclusiveLockBehavior());

    assertNull(properties.getSingleWriterLockBehavior());

    assertNull(properties.getScopedLockDetails());

    assertNull(properties.getBackendLockTimeoutMillis());

    assertNull(properties.getRetryAttempts());

    assertNull(properties.getMinTxnLockTimeoutMillis());

    assertNull(properties.getMaxTxnLockTimeoutMillis());

    assertFalse(properties.getReturnResponseControl());

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for a set of properties in which all properties have
   * been set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllPropertiesSpecified()
         throws Exception
  {
    final TransactionSettingsReqeustControlProperties properties =
         new TransactionSettingsReqeustControlProperties();
    properties.setTransactionName("the-transaction-name");
    properties.setCommitDurability(
         TransactionSettingsCommitDurability.PARTIALLY_SYNCHRONOUS);
    properties.setBackendExclusiveLockBehavior(
         TransactionSettingsBackendLockBehavior.ACQUIRE_AFTER_RETRIES);
    properties.setSingleWriterLockBehavior(
         TransactionSettingsBackendLockBehavior.ACQUIRE_BEFORE_RETRIES);
    properties.setScopedLockDetails(new TransactionSettingsScopedLockDetails(
         "the-scope-id",
         TransactionSettingsBackendLockBehavior.
              ACQUIRE_BEFORE_INITIAL_ATTEMPT));
    properties.setBackendLockTimeoutMillis(12345L);
    properties.setRetryAttempts(67);
    properties.setMinTxnLockTimeoutMillis(2345L);
    properties.setMaxTxnLockTimeoutMillis(6789L);
    properties.setReturnResponseControl(true);


    assertNotNull(properties.getTransactionName());
    assertEquals(properties.getTransactionName(), "the-transaction-name");

    assertNotNull(properties.getCommitDurability());
    assertEquals(properties.getCommitDurability(),
         TransactionSettingsCommitDurability.PARTIALLY_SYNCHRONOUS);

    assertNotNull(properties.getBackendExclusiveLockBehavior());
    assertEquals(properties.getBackendExclusiveLockBehavior(),
         TransactionSettingsBackendLockBehavior.ACQUIRE_AFTER_RETRIES);

    assertNotNull(properties.getSingleWriterLockBehavior());
    assertEquals(properties.getSingleWriterLockBehavior(),
         TransactionSettingsBackendLockBehavior.ACQUIRE_BEFORE_RETRIES);

    assertNotNull(properties.getScopedLockDetails());
    assertEquals(properties.getScopedLockDetails().getScopeIdentifier(),
         "the-scope-id");
    assertEquals(properties.getScopedLockDetails().getLockBehavior(),
         TransactionSettingsBackendLockBehavior.ACQUIRE_BEFORE_INITIAL_ATTEMPT);

    assertNotNull(properties.getBackendLockTimeoutMillis());
    assertEquals(properties.getBackendLockTimeoutMillis().longValue(), 12345L);

    assertNotNull(properties.getRetryAttempts());
    assertEquals(properties.getRetryAttempts().intValue(), 67);

    assertNotNull(properties.getMinTxnLockTimeoutMillis());
    assertEquals(properties.getMinTxnLockTimeoutMillis().longValue(), 2345L);

    assertNotNull(properties.getMaxTxnLockTimeoutMillis());
    assertEquals(properties.getMaxTxnLockTimeoutMillis().longValue(), 6789L);

    assertTrue(properties.getReturnResponseControl());

    assertNotNull(properties.toString());
  }
}
