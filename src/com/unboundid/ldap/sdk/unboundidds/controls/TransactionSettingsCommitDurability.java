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



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the options that may be specified for the transaction
 * commit durability when using the transaction settings request control.
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
 *
 * @see TransactionSettingsRequestControl
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum TransactionSettingsCommitDurability
{
  /**
   * Indicates that the commit should be non-synchronous.  Atomicity,
   * consistency, and isolation will be maintained for the transaction, but
   * there is no guarantee that the record of the transaction will be written
   * to disk by the time operation processing is complete and the response has
   * been returned to the client.  In the event of a JVM, operating system, or
   * hardware failure before the transaction record is actually flushed to disk,
   * then changes that are part of that transaction could be rolled back when
   * the server is started back up.
   */
  NON_SYNCHRONOUS(0),



  /**
   * Indicates that the commit should be partially synchronous.  Atomicity,
   * consistency, and isolation will be maintained for the transaction, and a
   * record of the transaction will be written to disk during the commit, but
   * that transaction record will not be synchronously flushed.  In the event of
   * an operating system or hardware failure before the transaction record is
   * actually flushed to disk, then changes that are part of that transaction
   * could be rolled back when the server is started back up.
   */
  PARTIALLY_SYNCHRONOUS(1),



  /**
   * Indicates that the commit should be fully synchronous.  Atomicity,
   * consistency, isolation, and durability will be maintained for the
   * transaction, and a record of the transaction will be flushed to disk before
   * the commit is completed.  In the event of a JVM, operating system, or
   * hardware failure, then any changes that are part of that transaction will
   * still be reflected in the database when the server is started back up (as
   * long as the database files are still intact).
   */
  FULLY_SYNCHRONOUS(2);



  // The integer value for this commit durability.
  private final int intValue;



  /**
   * Creates a new transaction settings commit durability with the provided
   * integer value.
   *
   * @param  intValue  The integer value for this commit durability.
   */
  TransactionSettingsCommitDurability(final int intValue)
  {
    this.intValue = intValue;
  }



  /**
   * Retrieves the integer value for this transaction settings commit durability
   * value.
   *
   * @return  The integer value for this transaction settings commit durability
   *          value.
   */
  public int intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the commit durability value with the specified integer value.
   *
   * @param  intValue  The integer value for the commit durability to retrieve.
   *
   * @return  The commit durability value with the specified integer value, or
   *          {@code null} if there is no such commit durability value.
   */
  @Nullable()
  public static TransactionSettingsCommitDurability valueOf(final int intValue)
  {
    for (final TransactionSettingsCommitDurability v : values())
    {
      if (v.intValue == intValue)
      {
        return v;
      }
    }

    return null;
  }



  /**
   * Retrieves the transaction settings commit durability with the specified
   * name.
   *
   * @param  name  The name of the transaction settings commit durability to
   *               retrieve.  It must not be {@code null}.
   *
   * @return  The requested transaction settings commit durability, or
   *          {@code null} if no such durability is defined.
   */
  @Nullable()
  public static TransactionSettingsCommitDurability forName(
                     @NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "nonsynchronous":
      case "non-synchronous":
      case "non_synchronous":
        return NON_SYNCHRONOUS;
      case "partiallysynchronous":
      case "partially-synchronous":
      case "partially_synchronous":
        return PARTIALLY_SYNCHRONOUS;
      case "fullysynchronous":
      case "fully-synchronous":
      case "fully_synchronous":
        return FULLY_SYNCHRONOUS;
      default:
        return null;
    }
  }
}
