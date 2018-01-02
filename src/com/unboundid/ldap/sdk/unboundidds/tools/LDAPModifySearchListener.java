/*
 * Copyright 2016-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2016-2018 Ping Identity Corporation
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



import java.util.List;
import java.util.Set;

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultListener;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFWriter;
import com.unboundid.util.Debug;
import com.unboundid.util.FixedRateBarrier;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides a search result listener that will be used in conjunction
 * with the {@link LDAPModify} tool to apply a modification to entries matching
 * a given search filter.
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
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class LDAPModifySearchListener
      implements SearchResultListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -583082242208798146L;



  // The search filter being processed.
  private final Filter searchFilter;

  // The fixed-rate barrier that should be used for rate limiting.
  private final FixedRateBarrier rateLimiter;

  // The connection pool to use to communicate with the directory server.
  private final LDAPConnectionPool connectionPool;

  // The associated LDAPModify tool instance.
  private final LDAPModify ldapModify;

  // The change record to with the changes to apply to entries returned from the
  // search.
  private final LDIFModifyChangeRecord sourceChangeRecord;

  // The reject writer to use to record information about failed modifications.
  private final LDIFWriter rejectWriter;

  // The set of controls to include in modify requests.
  private final List<Control> modifyControls;

  // The result code obtained from processing.
  private volatile ResultCode resultCode;

  // A set used to hold the DNs of the entries that have been processed.
  private final Set<DN> processedEntryDNs;



  /**
   * Creates a new search listener with the provided information.
   *
   * @param  ldapModify          The associated {@code LDAPModify} tool
   *                             instance.
   * @param  sourceChangeRecord  The change record with the changes to apply to
   *                             entries returned from the search.
   * @param  searchFilter        The search filter being processed.
   * @param  modifyControls      The set of controls to include in modify
   *                             requests.
   * @param  connectionPool      The connection pool to use to communicate with
   *                             the directory server.
   * @param  rateLimiter         The fixed-rate barrier to use to limit the rate
   *                             at which changes should be applied.  It may be
   *                             {@code null} if no rate limiting is needed.
   * @param  rejectWriter        The LDIF writer to use to record information
   *                             about failed operations.
   * @param  processedEntryDNs   A set used to hold the DNs of the entries that
   *                             have been processed.  This will be used in the
   *                             event that an error occurs during search
   *                             processing and it is necessary to re-issue a
   *                             search request.
   */
  LDAPModifySearchListener(final LDAPModify ldapModify,
                           final LDIFModifyChangeRecord sourceChangeRecord,
                           final Filter searchFilter,
                           final List<Control> modifyControls,
                           final LDAPConnectionPool connectionPool,
                           final FixedRateBarrier rateLimiter,
                           final LDIFWriter rejectWriter,
                           final Set<DN> processedEntryDNs)
  {
    this.ldapModify         = ldapModify;
    this.sourceChangeRecord = sourceChangeRecord;
    this.searchFilter       = searchFilter;
    this.modifyControls     = modifyControls;
    this.connectionPool     = connectionPool;
    this.rateLimiter        = rateLimiter;
    this.rejectWriter       = rejectWriter;
    this.processedEntryDNs  = processedEntryDNs;

    resultCode = ResultCode.SUCCESS;
  }



  /**
   * Retrieves the result code obtained from processing.
   *
   * @return  The result code obtained from processing.
   */
  ResultCode getResultCode()
  {
    return resultCode;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchEntryReturned(final SearchResultEntry searchEntry)
  {
    // Get the parsed DN of the search result entry to see if it has already
    // been processed.  In the unlikely event that the DN can't be parsed, just
    // assume that it hasn't been processed yet.
    DN parsedDN = null;
    try
    {
      parsedDN = searchEntry.getParsedDN();
      if (processedEntryDNs.contains(parsedDN))
      {
        return;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }


    // If we should perform rate limiting, then do that now.
    if (rateLimiter != null)
    {
      rateLimiter.await();
    }


    // Construct the LDIF modify change record to be processed.
    final LDIFModifyChangeRecord changeRecordFromSearchEntry =
         new LDIFModifyChangeRecord(searchEntry.getDN(),
              sourceChangeRecord.getModifications(),
              sourceChangeRecord.getControls());


    // Process the modification.
    try
    {
      final ResultCode rc = ldapModify.doModify(changeRecordFromSearchEntry,
           modifyControls, connectionPool, null, rejectWriter);
      if (rc != ResultCode.SUCCESS)
      {
        if ((resultCode == ResultCode.SUCCESS) ||
            (resultCode == ResultCode.NO_OPERATION))
        {
          resultCode = rc;
        }
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);

      // Even if it throws an exception, the doModify method should have done
      // the appropriate reporting for the failure.  We just need to check the
      // result code.
      if ((resultCode == ResultCode.SUCCESS) ||
          (resultCode == ResultCode.NO_OPERATION))
      {
        resultCode = le.getResultCode();
      }
    }


    // If we have a parsed DN, then add it to the set of DNs that we've already
    // processed.  It doesn't matter if the operation succeeded or not.
    if (parsedDN != null)
    {
      processedEntryDNs.add(parsedDN);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchReferenceReturned(
                   final SearchResultReference searchReference)
  {
    final StringBuilder urls = new StringBuilder();
    for (final String url : searchReference.getReferralURLs())
    {
      if (urls.length() > 0)
      {
        urls.append(", ");
      }

      urls.append(url);
    }

    final String comment = ERR_LDAPMODIFY_SEARCH_LISTENER_REFERRAL.get(
         sourceChangeRecord.getDN(), String.valueOf(searchFilter),
         urls.toString());
    ldapModify.writeRejectedChange(rejectWriter, comment, sourceChangeRecord);
  }
}
