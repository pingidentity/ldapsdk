/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1Long;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the transaction settings request
 * control.
 */
public final class TransactionSettingsRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with a control that does not specify any values for the
   * optional parameters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullParameters()
         throws Exception
  {
    TransactionSettingsRequestControl c = new TransactionSettingsRequestControl(
         true, null, null, null, null, null, null, null);

    c = new TransactionSettingsRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.38");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNull(c.getTransactionName());

    assertNull(c.getCommitDurability());

    assertNull(c.getBackendLockBehavior());

    assertNull(c.getBackendLockTimeoutMillis());

    assertNull(c.getRetryAttempts());

    assertNull(c.getMinTxnLockTimeoutMillis());

    assertNull(c.getMaxTxnLockTimeoutMillis());

    assertFalse(c.returnResponseControl());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior with a control that specifies values for all parameters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllParameters()
         throws Exception
  {
    TransactionSettingsRequestControl c = new TransactionSettingsRequestControl(
         false, "This is the name",
         TransactionSettingsCommitDurability.FULLY_SYNCHRONOUS,
         TransactionSettingsBackendLockBehavior.ACQUIRE_AFTER_RETRIES,
         123L, 45, 678L, 910L, true);

    c = new TransactionSettingsRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.38");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getTransactionName());
    assertEquals(c.getTransactionName(), "This is the name");

    assertNotNull(c.getCommitDurability());
    assertEquals(c.getCommitDurability(),
         TransactionSettingsCommitDurability.FULLY_SYNCHRONOUS);

    assertNotNull(c.getBackendLockBehavior());
    assertEquals(c.getBackendLockBehavior(),
         TransactionSettingsBackendLockBehavior.ACQUIRE_AFTER_RETRIES);

    assertNotNull(c.getBackendLockTimeoutMillis());
    assertEquals(c.getBackendLockTimeoutMillis().longValue(), 123L);

    assertNotNull(c.getRetryAttempts());
    assertEquals(c.getRetryAttempts().intValue(), 45);

    assertNotNull(c.getMinTxnLockTimeoutMillis());
    assertEquals(c.getMinTxnLockTimeoutMillis().longValue(), 678L);

    assertNotNull(c.getMaxTxnLockTimeoutMillis());
    assertEquals(c.getMaxTxnLockTimeoutMillis().longValue(), 910L);

    assertTrue(c.returnResponseControl());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to create a control that has a negative
   * backend lock timeout value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNegativeBackendLockTimeout()
         throws Exception
  {
    new TransactionSettingsRequestControl(true, null, null, null, -1L, null,
         null, null);
  }



  /**
   * Tests the behavior when trying to create a control that has a negative
   * retry attempts value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNegativeRetryAttempts()
         throws Exception
  {
    new TransactionSettingsRequestControl(true, null, null, null, null, -1,
         null, null);
  }



  /**
   * Tests the behavior when trying to create a control that has a negative
   * minimum transaction lock timeout value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNegativeMinTxnLockTimeout()
         throws Exception
  {
    new TransactionSettingsRequestControl(true, null, null, null, null, null,
         -1L, 1234L);
  }



  /**
   * Tests the behavior when trying to create a control that has a minimum
   * transaction lock timeout value without a corresponding maximum.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testMinTxnLockTimeoutWithoutMaximum()
         throws Exception
  {
    new TransactionSettingsRequestControl(true, null, null, null, null, null,
         1234L, null);
  }



  /**
   * Tests the behavior when trying to create a control that has a maximum
   * transaction lock timeout value without a corresponding minimum.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testMaxTxnLockTimeoutWithoutMinimum()
         throws Exception
  {
    new TransactionSettingsRequestControl(true, null, null, null, null, null,
         null, 1234L);
  }



  /**
   * Tests the behavior when trying to create a control that has a maximum
   * transaction lock timeout value that is less than the minimum.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testMaxTxnLockTimeoutLessThanMinimum()
         throws Exception
  {
    new TransactionSettingsRequestControl(true, null, null, null, null, null,
         5678L, 1234L);
  }



  /**
   * Tests the behavior when trying to decode a control that does not have a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    new TransactionSettingsRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.38", false));
  }



  /**
   * Tests the behavior when trying to decode a control whose value does not
   * represent a valid ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new TransactionSettingsRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.38", false,
              new ASN1OctetString("foo")));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence has
   * an unexpected element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceUnexpectedElementType()
         throws Exception
  {
    new TransactionSettingsRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.38", false,
              new ASN1OctetString(new ASN1Sequence(
                   new ASN1OctetString("foo")).encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence has
   * a commit durability with an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceInvalidCommitDurability()
         throws Exception
  {
    new TransactionSettingsRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.38", false,
              new ASN1OctetString(new ASN1Sequence(
                   new ASN1Enumerated((byte) 0x81, 1234)).encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence has
   * a backend lock behavior with an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceInvalidBackendLockBehavior()
         throws Exception
  {
    new TransactionSettingsRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.38", false,
              new ASN1OctetString(new ASN1Sequence(
                   new ASN1Enumerated((byte) 0x82, 5678)).encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence has
   * a backend lock timeout with an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceInvalidBackendLockTimeout()
         throws Exception
  {
    new TransactionSettingsRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.38", false,
              new ASN1OctetString(new ASN1Sequence(
                   new ASN1Long((byte) 0x83, -1L)).encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence has
   * a retry attempts element with an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceInvalidRetryAttempts()
         throws Exception
  {
    new TransactionSettingsRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.38", false,
              new ASN1OctetString(new ASN1Sequence(
                   new ASN1Integer((byte) 0x84, -1)).encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence has
   * a minimum lock timeout with an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceInvalidMinLockTimeout()
         throws Exception
  {
    new TransactionSettingsRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.38", false,
              new ASN1OctetString(new ASN1Sequence(
                   new ASN1Sequence((byte) 0xA5,
                        new ASN1Long(-1L),
                        new ASN1Long(1234L))).encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence has
   * a maximum lock timeout with an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceInvalidMaxLockTimeout()
         throws Exception
  {
    new TransactionSettingsRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.38", false,
              new ASN1OctetString(new ASN1Sequence(
                   new ASN1Sequence((byte) 0xA5,
                        new ASN1Long(5678L),
                        new ASN1Long(1234L))).encode())));
  }
}
