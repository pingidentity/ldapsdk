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

import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines a number of properties for use in conjunction with the
 * {@link TransactionSettingsRequestControl}.
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
public final class TransactionSettingsReqeustControlProperties
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1124435803639477902L;



  // Indicates whether to return a response control.
  private boolean returnResponseControl;

  // The number of times to retry if a lock conflict exception is encountered.
  @Nullable private Integer retryAttempts;

  // The backend lock timeout, in milliseconds.
  @Nullable private Long backendLockTimeoutMillis;

  // The maximum transaction lock timeout, in milliseconds.
  @Nullable private Long maxTxnLockTimeoutMillis;

  // The minimum transaction lock timeout, in milliseconds.
  @Nullable private Long minTxnLockTimeoutMillis;

  // The requested transaction name.
  @Nullable private String transactionName;

  // The behavior to use with regard to requesting the exclusive backend lock.
  @Nullable private TransactionSettingsBackendLockBehavior backendLockBehavior;

  // The requested commit durability setting.
  @Nullable private TransactionSettingsCommitDurability commitDurability;

  // The behavior to use with regard to requesting the scoped lock.
  @Nullable private TransactionSettingsScopedLockDetails scopedLockDetails;



  /**
   * Creates a new set of properties with all default values.
   */
  public TransactionSettingsReqeustControlProperties()
  {
    returnResponseControl = false;
    retryAttempts = null;
    backendLockTimeoutMillis = null;
    maxTxnLockTimeoutMillis = null;
    minTxnLockTimeoutMillis = null;
    transactionName = null;
    backendLockBehavior = null;
    commitDurability = null;
    scopedLockDetails = null;
  }



  /**
   * Retrieves the name to assign to the associated transaction, if specified.
   *
   * @return  The name to assign to the associated transaction, or {@code null}
   *          if none has been specified.
   */
  @Nullable()
  public String getTransactionName()
  {
    return transactionName;
  }



  /**
   * Specifies the name to assign to the associated transaction.
   *
   * @param  transactionName  The name to assign to the associated transaction,
   *                          or {@code null} if no transaction name should be
   *                          used.
   */
  public void setTransactionName(@Nullable final String transactionName)
  {
    this.transactionName = transactionName;
  }



  /**
   * Retrieves the commit durability that should be used for the associated
   * transaction, if specified.
   *
   * @return  The commit durability that should be used for the associated
   *          transaction, or {@code null} if none has been specified and the
   *          server should determine the commit durability.
   */
  @Nullable()
  public TransactionSettingsCommitDurability getCommitDurability()
  {
    return commitDurability;
  }



  /**
   * Specifies the commit durability that should be used for the associated
   * transaction.
   *
   * @param  commitDurability  The commit durability that should be used for
   *                           the associated transaction.  It may be
   *                           {@code null} if the server should determine the
   *                           commit durability.
   */
  public void setCommitDurability(
       @Nullable final TransactionSettingsCommitDurability
            commitDurability)
  {
    this.commitDurability = commitDurability;
  }



  /**
   * Retrieves the backend lock behavior that should be used for the associated
   * transaction, if specified.
   *
   * @return  The backend lock behavior that should be used for the associated
   *          transaction, or {@code null} if none has been specified and the
   *          server should determine the backend lock behavior.
   */
  @Nullable()
  public TransactionSettingsBackendLockBehavior getBackendLockBehavior()
  {
    return backendLockBehavior;
  }



  /**
   * Specifies the backend lock behavior that should be used for the associated
   * transaction.
   *
   * @param  backendLockBehavior  The backend lock behavior that should be used
   *                              for the associated transaction.  It may be
   *                              {@code null} if the server should determine
   *                              the backend lock behavior.
   */
  public void setBackendLockBehavior(
       @Nullable final TransactionSettingsBackendLockBehavior
            backendLockBehavior)
  {
    this.backendLockBehavior = backendLockBehavior;
  }



  /**
   * Retrieves the backend lock timeout (in milliseconds) that should be used
   * for the associated transaction, if specified.
   *
   * @return  The backend lock timeout (in milliseconds) that should be used for
   *          the associated transaction, or {@code null} if none has been
   *          specified and the server should determine the backend lock
   *          timeout.
   */
  @Nullable()
  public Long getBackendLockTimeoutMillis()
  {
    return backendLockTimeoutMillis;
  }



  /**
   * Specifies the backend lock timeout (in milliseconds) that should be used
   * for the associated transaction.
   *
   * @param  backendLockTimeoutMillis  The backend lock timeout (in
   *                                   milliseconds) that should be used for
   *                                   the associated transaction.  It may be
   *                                   {@code null} if the server should
   *                                   determine the backend lock timeout.
   */
  public void setBackendLockTimeoutMillis(
       @Nullable final Long backendLockTimeoutMillis)
  {
    this.backendLockTimeoutMillis = backendLockTimeoutMillis;
  }



  /**
   * Retrieves the maximum number of times that the transaction may be retried
   * if the initial attempt fails due to a lock conflict, if specified.
   *
   * @return  The maximum number of times that the transaction may be retried if
   *          the initial attempt fails due to a lock conflict, or {@code null}
   *          if none has been specified and the server should determine the
   *          number of retry attempts.
   */
  @Nullable()
  public Integer getRetryAttempts()
  {
    return retryAttempts;
  }



  /**
   * Specifies the maximum number of times that the transaction may be retried
   * if the initial attempt fails due to a lock conflict.
   *
   * @param  retryAttempts  The maximum number of times that the transaction may
   *                        be retried if the initial attempt fails due to a
   *                        lock conflict.  It may be {@code null} if the server
   *                        should determine the number of retry attempts.
   */
  public void setRetryAttempts(@Nullable final Integer retryAttempts)
  {
    this.retryAttempts = retryAttempts;
  }



  /**
   * Retrieves the minimum transaction lock timeout (in milliseconds) that
   * should be used for the associated transaction, if specified.  This is the
   * timeout value that will be used for the first attempt.  Any subsequent
   * attempts will have a lock timeout that is between the minimum and maximum
   * timeout value.
   *
   * @return  The minimum lock timeout (in milliseconds) that should
   *          be used for the associated transaction, or {@code null} if none
   *          has been specified and the server should determine the minimum
   *          transaction lock timeout.
   */
  @Nullable()
  public Long getMinTxnLockTimeoutMillis()
  {
    return minTxnLockTimeoutMillis;
  }



  /**
   * Specifies the minimum transaction lock timeout (in milliseconds) that
   * should be used for the associated transaction.  This is the timeout value
   * that will be used for the first attempt.  Any subsequent attempts will have
   * a lock timeout that is between the minimum and maximum timeout value.
   *
   * @param  minTxnLockTimeoutMillis  The minimum lock timeout (in milliseconds)
   *                                  that should be used for the associated
   *                                  transaction.  It may be {@code null} if
   *                                  the server should determine the minimum
   *                                  transaction lock timeout.
   */
  public void setMinTxnLockTimeoutMillis(
       @Nullable final Long minTxnLockTimeoutMillis)
  {
    this.minTxnLockTimeoutMillis = minTxnLockTimeoutMillis;
  }



  /**
   * Retrieves the maximum transaction lock timeout (in milliseconds) that
   * should be used for the associated transaction, if specified.  The timeout
   * to be used for any retries will be between the minimum and maximum lock
   * timeout values.
   *
   * @return  The maximum lock timeout (in milliseconds) that should
   *          be used for the associated transaction, or {@code null} if none
   *          has been specified and the server should determine the maximum
   *          transaction lock timeout.
   */
  @Nullable()
  public Long getMaxTxnLockTimeoutMillis()
  {
    return maxTxnLockTimeoutMillis;
  }



  /**
   * Specifies the maximum transaction lock timeout (in milliseconds) that
   * should be used for the associated transaction.  The timeout to be used for
   * any retries will be between the minimum and maximum lock timeout values.
   *
   * @param maxTxnLockTimeoutMillis  The maximum lock timeout (in milliseconds)
   *                                 that should be used for the associated
   *                                 transaction.  It may be {@code null} if the
   *                                 server should determine the maximum
   *                                 transaction lock timeout.
   */
  public void setMaxTxnLockTimeoutMillis(
       @Nullable final Long maxTxnLockTimeoutMillis)
  {
    this.maxTxnLockTimeoutMillis = maxTxnLockTimeoutMillis;
  }



  /**
   * Retrieves details about the conditions under which to attempt to acquire a
   * scoped lock, if any.
   *
   * @return  Details about the conditions under which to attempt to acquire a
   *          scoped lock, or {@code null} if no attempt should be made to
   *          acquire a scoped lock.
   */
  @Nullable()
  public TransactionSettingsScopedLockDetails getScopedLockDetails()
  {
    return scopedLockDetails;
  }



  /**
   * Specifies details about the conditions under which to attempt to acquire a
   * scoped lock.
   *
   * @param  scopedLockDetails  Details about the conditions under which to
   *                            attempt to acquire a scoped lock.  It may be
   *                            {@code null} if no attempt should be made to
   *                            acquire a scoped lock.
   */
  public void setScopedLockDetails(
       @Nullable final TransactionSettingsScopedLockDetails scopedLockDetails)
  {
    this.scopedLockDetails = scopedLockDetails;
  }



  /**
   * Indicates whether to return a response control with transaction-related
   * information collected over the course of processing the associated
   * operation.
   *
   * @return  {@code true} if the server should return a response control with
   *          transaction-related information, or {@code false} if not.
   */
  public boolean getReturnResponseControl()
  {
    return returnResponseControl;
  }



  /**
   * Indicates whether to return a response control with transaction-related
   * information collected over the course of processing the associated
   * operation.
   *
   * @param  returnResponseControl  Specifies whether the server should return a
   *                                response control with transaction-related
   *                                information.
   */
  public void setReturnResponseControl(final boolean returnResponseControl)
  {
    this.returnResponseControl = returnResponseControl;
  }



  /**
   * Retrieves a string representation of the transaction settings request
   * control properties.
   *
   * @return  A string representation of the transaction settings request
   *          control properties.
   */
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of the transaction settings request control
   * properties to the provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.  It must not be {@code null}.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("TransactionSettingsReqeustControlProperties(");

    boolean appended = false;
    if (transactionName != null)
    {
      buffer.append("transactionName='");
      buffer.append(transactionName);
      buffer.append('\'');
      appended = true;

    }

    if (commitDurability != null)
    {
      if (appended)
      {
        buffer.append(", ");
      }

      buffer.append("commitDurability='");
      buffer.append(commitDurability.name());
      buffer.append('\'');
      appended = true;
    }


    if (backendLockBehavior != null)
    {
      if (appended)
      {
        buffer.append(", ");
      }

      buffer.append("backendLockBehavior='");
      buffer.append(backendLockBehavior.name());
      buffer.append('\'');
      appended = true;
    }


    if (backendLockTimeoutMillis != null)
    {
      if (appended)
      {
        buffer.append(", ");
      }

      buffer.append("backendLockTimeoutMillis=");
      buffer.append(backendLockTimeoutMillis);
      appended = true;
    }


    if (retryAttempts != null)
    {
      if (appended)
      {
        buffer.append(", ");
      }

      buffer.append("retryAttempts=");
      buffer.append(retryAttempts);
      appended = true;
    }


    if (minTxnLockTimeoutMillis != null)
    {
      if (appended)
      {
        buffer.append(", ");
      }

      buffer.append("minTxnLockTimeoutMillis=");
      buffer.append(minTxnLockTimeoutMillis);
      appended = true;
    }


    if (maxTxnLockTimeoutMillis != null)
    {
      if (appended)
      {
        buffer.append(", ");
      }

      buffer.append("maxTxnLockTimeoutMillis=");
      buffer.append(maxTxnLockTimeoutMillis);
      appended = true;
    }


    if (scopedLockDetails != null)
    {
      if (appended)
      {
        buffer.append(", ");
      }

      buffer.append("scopedLockDetails=");
      scopedLockDetails.toString(buffer);
      appended = true;
    }

    if (appended)
    {
      buffer.append(", ");
    }

    buffer.append("returnResponseControl=");
    buffer.append(returnResponseControl);
    buffer.append(')');
  }
}
