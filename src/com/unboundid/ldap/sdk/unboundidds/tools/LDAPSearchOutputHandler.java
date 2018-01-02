/*
 * Copyright 2017-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an API that may be implemented by classes that format
 * and output the results for the {@link LDAPSearch} tool.
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
 */
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
abstract class LDAPSearchOutputHandler
{
  /**
   * Handles the processing required for formatting a header that describes
   * the way in which the data will be formatted.  This will be displayed at
   * the beginning of the output (including at the top of each file if the
   * output from multiple searches should be written to separate files).
   */
  abstract void formatHeader();



  /**
   * Handles the processing required for formatting and outputting the provided
   * search result entry.
   *
   * @param  entry  The search result entry to be processed.
   */
  abstract void formatSearchResultEntry(SearchResultEntry entry);



  /**
   * Handles the processing required for formatting and outputting the provided
   * search result reference.
   *
   * @param  ref  The search result reference to be processed.
   */
  abstract void formatSearchResultReference(SearchResultReference ref);



  /**
   * Handles the processing required for formatting and outputting the provided
   * LDAP result.
   *
   * @param  result  The LDAP result to be processed.  It may or may not be a
   *                 search result.
   */
  abstract void formatResult(LDAPResult result);



  /**
   * Handles the processing required for formatting and outputting the provided
   * unsolicited notification.
   *
   * @param  connection    The connection on which the unsolicited notification
   *                       was received.
   * @param  notification  The unsolicited notification that was received.
   */
  abstract void formatUnsolicitedNotification(LDAPConnection connection,
                                              ExtendedResult notification);
}
