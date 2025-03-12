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



import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Long;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a data structure that holds information that may be used
 * if the server needs to acquire a scoped lock that may apply to a subset of
 * related requests within a backend, without affecting other unrelated
 * operations being processed in that backend.
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
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class TransactionSettingsScopedLockDetails
       implements Serializable
{
  /**
   * The BER type for the element used to indicate the timeout to use when
   * tryign to encode the scoped lock.
   */
  private static final byte TYPE_SCOPED_LOCK_TIMEOUT_MILLIS = (byte) 0x88;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1374000956873071172L;



  // The maximum length of time, in milliseconds, that the server should wait
  // while attempting to acquire the lock.
  @Nullable private final Long lockTimeoutMillis;

  // A string that identifies which scoped lock to acquire.
  @NotNull private final String scopeIdentifier;

  // The behavior that should be used when acquiring the lock.
  @NotNull private final TransactionSettingsBackendLockBehavior lockBehavior;



  /**
   * Creates a new scoped lock details object with the provided information.
   *
   * @param  scopeIdentifier    A string that identifies which scoped lock to
   *                            acquire.  It must not be {@code null}.
   * @param  lockBehavior       The behavior that indicates when the server
   *                            should attempt to acquire the scoped lock.  It
   *                            must not be {@code null}, and should not be
   *                            {@code DO_NOT_ACQUIRE}.
   * @param  lockTimeoutMillis  The maximum length of time, in milliseconds,
   *                            that the server should wait while attempting to
   *                            acquire the lock.  This may be {@code null} if
   *                            the server should automatically determine the
   *                            timeout to use.
   */
  public TransactionSettingsScopedLockDetails(
       @NotNull final String scopeIdentifier,
       @NotNull final TransactionSettingsBackendLockBehavior lockBehavior,
       @Nullable final Long lockTimeoutMillis)
  {
    this.scopeIdentifier = scopeIdentifier;
    this.lockBehavior = lockBehavior;
    this.lockTimeoutMillis = lockTimeoutMillis;
  }



  /**
   * Retrieves s string that identifies which scoped lock to acquire.
   *
   * @return  A string that identifies which scoped lock to acquire.
   */
  @NotNull()
  public String getScopeIdentifier()
  {
    return scopeIdentifier;
  }



  /**
   * Retrieves the behavior that indicates when the lock should be acquired.
   *
   * @return  The behavior that indicates when the lock should be acquired.
   */
  @NotNull()
  public TransactionSettingsBackendLockBehavior getLockBehavior()
  {
    return lockBehavior;
  }



  /**
   * Retrieves the maximum length of time, in milliseconds, that the server
   * should wait while attempting to acquire the scoped lock.
   *
   * @return  The maximum length of time, in milliseconds, that the server
   *          should wait while attempting to acquire the scoped lock, or
   *          {@code null} if the server should automatically determine the
   *          timeout to use.
   */
  @Nullable()
  public Long getLockTimeoutMillis()
  {
    return lockTimeoutMillis;
  }



  /**
   * Encodes the scoped lock details into an ASN.1 element for inclusion in a
   * transaction settings request control.
   *
   * @return  The ASN.1 element containing the encoded scoped lock details, or
   *          {@code null} if no scoped lock is needed (as indicated by a
   *          lock behavior of {@code DO_NOT_ACQUIRE}).
   */
  @Nullable()
  public ASN1Element encode()
  {
    if (lockBehavior == TransactionSettingsBackendLockBehavior.DO_NOT_ACQUIRE)
    {
      return null;
    }

    final List<ASN1Element> elements = new ArrayList<>(3);
    elements.add(new ASN1OctetString(scopeIdentifier));
    elements.add(new ASN1Enumerated(lockBehavior.intValue()));

    if (lockTimeoutMillis != null)
    {
      elements.add(new ASN1Long(TYPE_SCOPED_LOCK_TIMEOUT_MILLIS,
           lockTimeoutMillis));
    }

    return new ASN1Sequence(
         TransactionSettingsRequestControl.TYPE_SCOPED_LOCK_DETAILS,
         elements);
  }



  /**
   * Decodes the provided ASN.1 element as a set of scoped lock settings.
   *
   * @param  element  The ASN.1 element to decode as a set of scoped lock
   *                  settings.  It may be {@code null} if the associated
   *                  transaction settings request control did not include any
   *                  scoped lock settings.
   *
   * @return  The decoded scoped lock settings.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided ASN.1 element as a set of scoped lock
   *                         settings.
   */
  @Nullable()
  public static TransactionSettingsScopedLockDetails decode(
              @Nullable final ASN1Element element)
         throws LDAPException
  {
    if (element == null)
    {
      return null;
    }

    try
    {
      final ASN1Element[] elements = element.decodeAsSequence().elements();
      final String scopeIdentifier =
           elements[0].decodeAsOctetString().stringValue();

      final int lockBehaviorIntValue =
           elements[1].decodeAsEnumerated().intValue();
      final TransactionSettingsBackendLockBehavior lockBehavior =
           TransactionSettingsBackendLockBehavior.valueOf(lockBehaviorIntValue);

      Long lockTimeoutMillis = null;
      for (int i=2; i < elements.length; i++)
      {
        switch (elements[i].getType())
        {
          case TYPE_SCOPED_LOCK_TIMEOUT_MILLIS:
            lockTimeoutMillis = elements[i].decodeAsLong().longValue();
            break;
        }
      }

      return new TransactionSettingsScopedLockDetails(scopeIdentifier,
           lockBehavior, lockTimeoutMillis);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.PROTOCOL_ERROR,
           ERR_TXN_SETTINGS_SCOPED_LOCK_DETAILS_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves a string representation of the scoped lock details.
   *
   * @return  A string representation of the scoped lock details.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of the scoped lock details to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("TransactionSettingsScopedLockDetails(scopeIdentifier='");
    buffer.append(scopeIdentifier);
    buffer.append("', lockBehavior='");
    buffer.append(lockBehavior.name());

    if (lockTimeoutMillis != null)
    {
      buffer.append(", lockTimeoutMillis=");
      buffer.append(lockTimeoutMillis);
    }

    buffer.append("')");
  }
}
