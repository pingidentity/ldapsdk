/*
 * Copyright 2014-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the options that may be specified for the transaction
 * commit durability when using the transaction settings request control.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
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
}
