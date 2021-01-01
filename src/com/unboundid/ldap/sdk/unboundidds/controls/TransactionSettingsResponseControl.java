/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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



import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a response control that may be used to provide the
 * client with information about transaction-related information over the
 * course of the associated operation.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * This control has an OID of 1.3.6.1.4.1.30221.2.5.39.  It should have a
 * criticality of {@code false}, and a value with the following encoding:
 * <PRE>
 *   TransactionSettingsResponseValue ::= SEQUENCE {
 *        numLockConflicts        [0] INTEGER
 *        backendLockAcquired     [1] BOOLEAN,
 *        ... }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TransactionSettingsResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.39) for the transaction settings response
   * control.
   */
  @NotNull public static final String TRANSACTION_SETTINGS_RESPONSE_OID =
       "1.3.6.1.4.1.30221.2.5.39";



  /**
   * The BER type for the value element used to hold the number of lock
   * conflicts encountered during the course of processing.
   */
  private static final byte TYPE_NUM_LOCK_CONFLICTS = (byte) 0x80;



  /**
   * The BER type for the value element used to hold the number of lock
   * conflicts encountered during the course of processing.
   */
  private static final byte TYPE_BACKEND_LOCK_ACQUIRED = (byte) 0x81;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7290122856855738454L;



  // Indicates whether the exclusive backend lock was acquired at any point
  // during the course of processing the operation.
  private final boolean backendLockAcquired;

  // The number of lock conflicts encountered during the course of processing
  // the operation.
  private final int numLockConflicts;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  TransactionSettingsResponseControl()
  {
    backendLockAcquired = false;
    numLockConflicts = -1;
  }



  /**
   * Creates a new transaction settings response control with the provided
   * information.
   *
   * @param  numLockConflicts     The number of lock conflicts encountered
   *                              during the course of processing the operation.
   * @param  backendLockAcquired  Indicates whether the exclusive backend lock
   *                              was acquired at any point during the course of
   *                              processing the operation.
   */
  public TransactionSettingsResponseControl(final int numLockConflicts,
                                            final boolean backendLockAcquired)
  {
    super(TRANSACTION_SETTINGS_RESPONSE_OID, false,
         encodeValue(numLockConflicts, backendLockAcquired));

    this.numLockConflicts = numLockConflicts;
    this.backendLockAcquired = backendLockAcquired;
  }



  /**
   * Creates a new transaction settings response control with the provided
   * information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be considered
   *                     critical.
   * @param  value       The value for the control.
   *
   * @throws LDAPException  If the provided information cannot be used to
   *                         create a valid soft delete response control.
   */
  public TransactionSettingsResponseControl(@NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_TXN_SETTINGS_RESPONSE_NO_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      numLockConflicts = ASN1Integer.decodeAsInteger(elements[0]).intValue();
      backendLockAcquired =
           ASN1Boolean.decodeAsBoolean(elements[1]).booleanValue();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_TXN_SETTINGS_RESPONSE_ERROR_DECODING_VALUE.get(
                StaticUtils.getExceptionMessage(e)));
    }
  }



  /**
   * Creates an encoded control value with the provided information.
   *
   * @param  numLockConflicts     The number of lock conflicts encountered
   *                              during the course of processing the operation.
   * @param  backendLockAcquired  Indicates whether the exclusive backend lock
   *                              was acquired at any point during the course of
   *                              processing the operation.
   *
   * @return  An encoded control value with the provided information.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(final int numLockConflicts,
                                             final boolean backendLockAcquired)
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Integer(TYPE_NUM_LOCK_CONFLICTS, numLockConflicts),
         new ASN1Boolean(TYPE_BACKEND_LOCK_ACQUIRED, backendLockAcquired));
    return new ASN1OctetString(valueSequence.encode());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public TransactionSettingsResponseControl decodeControl(
              @NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new TransactionSettingsResponseControl(oid, isCritical, value);
  }



  /**
   * Retrieves the number of lock conflicts encountered during the course of
   * processing the associated operation.
   *
   * @return  The number of lock conflicts encountered during the course of
   *          processing the associated operation.
   */
  public int getNumLockConflicts()
  {
    return numLockConflicts;
  }



  /**
   * Indicates whether the exclusive backend lock was acquired at any point
   * during the course of processing the associated operation.
   *
   * @return  {@code true} if the backend lock was acquired, or {@code false} if
   *          not.
   */
  public boolean backendLockAcquired()
  {
    return backendLockAcquired;
  }



  /**
   * Extracts a transaction settings response control from the provided extended
   * result.
   *
   * @param  extendedResult  The extended result from which to retrieve the
   *                         transaction settings response control.
   *
   * @return  The transaction settings response control contained in the
   *          provided extended result, or {@code null} if the result did not
   *          contain a transaction settings response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the transaction settings response control
   *                         contained in the provided result.
   */
  @Nullable()
  public static TransactionSettingsResponseControl get(
                     @NotNull final ExtendedResult extendedResult)
         throws LDAPException
  {
    final Control c =
         extendedResult.getResponseControl(TRANSACTION_SETTINGS_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof TransactionSettingsResponseControl)
    {
      return (TransactionSettingsResponseControl) c;
    }
    else
    {
      return new TransactionSettingsResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_TXN_SETTINGS_RESPONSE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("TransactionSettingsResponseControl(numLockConflicts=");
    buffer.append(numLockConflicts);
    buffer.append(", backendLockAcquired=");
    buffer.append(backendLockAcquired);
    buffer.append(')');
  }
}
