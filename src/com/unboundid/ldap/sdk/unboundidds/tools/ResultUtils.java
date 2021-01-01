/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityResponseControl;
import com.unboundid.ldap.sdk.controls.ContentSyncDoneControl;
import com.unboundid.ldap.sdk.controls.ContentSyncStateControl;
import com.unboundid.ldap.sdk.controls.EntryChangeNotificationControl;
import com.unboundid.ldap.sdk.controls.PasswordExpiredControl;
import com.unboundid.ldap.sdk.controls.PasswordExpiringControl;
import com.unboundid.ldap.sdk.controls.PersistentSearchChangeType;
import com.unboundid.ldap.sdk.controls.PostReadResponseControl;
import com.unboundid.ldap.sdk.controls.PreReadResponseControl;
import com.unboundid.ldap.sdk.controls.ServerSideSortResponseControl;
import com.unboundid.ldap.sdk.controls.SimplePagedResultsControl;
import com.unboundid.ldap.sdk.controls.VirtualListViewResponseControl;
import com.unboundid.ldap.sdk.extensions.AbortedTransactionExtendedResult;
import com.unboundid.ldap.sdk.extensions.EndTransactionExtendedResult;
import com.unboundid.ldap.sdk.extensions.NoticeOfDisconnectionExtendedResult;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedResult;
import com.unboundid.ldap.sdk.extensions.StartTransactionExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.controls.AccountUsableResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.AssuredReplicationLocalLevel;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationRemoteLevel;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationServerResult;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationServerResultCode;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.AuthenticationFailureReason;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GeneratePasswordResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetAuthorizationEntryResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetBackendSetIDResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetPasswordPolicyStateIssuesResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetRecentLoginHistoryResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.GetServerIDResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetUserResourceLimitsResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            IntermediateClientResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            IntermediateClientResponseValue;
import com.unboundid.ldap.sdk.unboundidds.controls.JoinedEntry;
import com.unboundid.ldap.sdk.unboundidds.controls.JoinResultControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            MatchingEntryCountResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.PasswordPolicyErrorType;
import com.unboundid.ldap.sdk.unboundidds.controls.
            PasswordPolicyResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.PasswordPolicyWarningType;
import com.unboundid.ldap.sdk.unboundidds.controls.
            PasswordQualityRequirementValidationResult;
import com.unboundid.ldap.sdk.unboundidds.controls.
            PasswordValidationDetailsResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.RecentLoginHistory;
import com.unboundid.ldap.sdk.unboundidds.controls.RecentLoginHistoryAttempt;
import com.unboundid.ldap.sdk.unboundidds.controls.SoftDeleteResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            TransactionSettingsResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.UniquenessResponseControl;
import com.unboundid.ldap.sdk.unboundidds.extensions.MultiUpdateChangesApplied;
import com.unboundid.ldap.sdk.unboundidds.extensions.MultiUpdateExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityError;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityNotice;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityWarning;
import com.unboundid.ldap.sdk.unboundidds.extensions.PasswordQualityRequirement;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides a set of utility methods for formatting operation
 * results.
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
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ResultUtils
{
  /**
   * Ensures that this utility class can't be instantiated.
   */
  private ResultUtils()
  {
    // No implementation required.
  }



  /**
   * Retrieves a list of strings that comprise a formatted representation of the
   * provided result.
   *
   * @param  result    The result to be formatted.
   * @param  comment   Indicates whether to prefix each line with an octothorpe
   *                   to indicate that it is a comment.
   * @param  indent    The number of spaces to indent each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   *
   * @return  A list of strings that comprise a formatted representation of the
   *          provided result.
   */
  @NotNull()
  public static List<String> formatResult(@NotNull final LDAPResult result,
                                          final boolean comment,
                                          final int indent, final int maxWidth)
  {
    final ArrayList<String> lines = new ArrayList<>(10);
    formatResult(lines, result, comment, false, indent, maxWidth);
    return lines;
  }



  /**
   * Retrieves a list of strings that comprise a formatted representation of the
   * result encapsulated by the provided exception.
   *
   * @param  ldapException  The exception to use to obtain the result to format.
   * @param  comment        Indicates whether to prefix each line with an
   *                        octothorpe to indicate that it is a comment.
   * @param  indent         The number of spaces to indent each line.
   * @param  maxWidth       The maximum length of each line in characters,
   *                        including the comment prefix and indent.
   *
   * @return  A list of strings that comprise a formatted representation of the
   *          result encapsulated by the provided exception.
   */
  @NotNull()
  public static List<String> formatResult(
              @NotNull final LDAPException ldapException,
              final boolean comment,
              final int indent, final int maxWidth)
  {
    return formatResult(ldapException.toLDAPResult(), comment, indent,
         maxWidth);
  }



  /**
   * Adds a multi-line string representation of the provided result to the
   * given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  result    The result to be formatted.
   * @param  comment   Indicates whether to prefix each line with an octothorpe
   *                   to indicate that it is a comment.
   * @param  inTxn     Indicates whether the operation is part of an active
   *                   transaction.
   * @param  indent    The number of spaces to indent each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  public static void formatResult(@NotNull final List<String> lines,
                                  @NotNull final LDAPResult result,
                                  final boolean comment, final boolean inTxn,
                                  final int indent, final int maxWidth)
  {
    formatResult(lines, result, inTxn, createPrefix(comment, indent), maxWidth);
  }



  /**
   * Adds a multi-line string representation of the provided result to the
   * given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  result    The result to be formatted.
   * @param  inTxn     Indicates whether the operation is part of an active
   *                   transaction.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void formatResult(@NotNull final List<String> lines,
                                   @NotNull final LDAPResult result,
                                   final boolean inTxn,
                                   @NotNull final String prefix,
                                   final int maxWidth)
  {
    // Format the result code.  If it's a success result but the operation was
    // part of a transaction, then indicate that no change has actually been
    // made yet.
    final ResultCode resultCode = result.getResultCode();
    wrap(lines, INFO_RESULT_UTILS_RESULT_CODE.get(String.valueOf(resultCode)),
         prefix, maxWidth);
    if (inTxn && (resultCode == ResultCode.SUCCESS))
    {
      wrap(lines, INFO_RESULT_UTILS_SUCCESS_WITH_TXN.get(), prefix, maxWidth);
    }


    // Format the diagnostic message, if there is one.
    final String diagnosticMessage = result.getDiagnosticMessage();
    if (diagnosticMessage != null)
    {
      wrap(lines, INFO_RESULT_UTILS_DIAGNOSTIC_MESSAGE.get(diagnosticMessage),
           prefix, maxWidth);
    }


    // Format the matched DN, if there is one.
    final String matchedDN = result.getMatchedDN();
    if (matchedDN != null)
    {
      wrap(lines, INFO_RESULT_UTILS_MATCHED_DN.get(matchedDN), prefix,
           maxWidth);
    }


    // If there are any referral URLs, then display them.
    final String[] referralURLs = result.getReferralURLs();
    if (referralURLs != null)
    {
      for (final String referralURL : referralURLs)
      {
        wrap(lines, INFO_RESULT_UTILS_REFERRAL_URL.get(referralURL), prefix,
             maxWidth);
      }
    }


    if (result instanceof SearchResult)
    {
      final SearchResult searchResult = (SearchResult) result;

      // We'll always display the search entry count if we know it.
      final int numEntries = searchResult.getEntryCount();
      if (numEntries >= 0)
      {
        wrap(lines, INFO_RESULT_UTILS_NUM_SEARCH_ENTRIES.get(numEntries),
             prefix, maxWidth);
      }

      // We'll only display the search reference count if it's greater than
      // zero.
      final int numReferences = searchResult.getReferenceCount();
      if (numReferences > 0)
      {
        wrap(lines, INFO_RESULT_UTILS_NUM_SEARCH_REFERENCES.get(numReferences),
             prefix, maxWidth);
      }
    }
    else if (result instanceof StartTransactionExtendedResult)
    {
      final StartTransactionExtendedResult startTxnResult =
           (StartTransactionExtendedResult) result;
      final ASN1OctetString txnID = startTxnResult.getTransactionID();
      if (txnID != null)
      {
        if (StaticUtils.isPrintableString(txnID.getValue()))
        {
          wrap(lines,
               INFO_RESULT_UTILS_START_TXN_RESULT_TXN_ID.get(
                    txnID.stringValue()),
               prefix, maxWidth);
        }
        else
        {
          wrap(lines,
               INFO_RESULT_UTILS_START_TXN_RESULT_TXN_ID.get(
                    "0x" + StaticUtils.toHex(txnID.getValue())),
               prefix, maxWidth);
        }
      }
    }
    else if (result instanceof EndTransactionExtendedResult)
    {
      final EndTransactionExtendedResult endTxnResult =
           (EndTransactionExtendedResult) result;
      final int failedOpMessageID = endTxnResult.getFailedOpMessageID();
      if (failedOpMessageID > 0)
      {
        wrap(lines,
             INFO_RESULT_UTILS_END_TXN_RESULT_FAILED_MSG_ID.get(
                  failedOpMessageID),
             prefix, maxWidth);
      }

      final Map<Integer,Control[]> controls =
           endTxnResult.getOperationResponseControls();
      if (controls != null)
      {
        for (final Map.Entry<Integer,Control[]> e : controls.entrySet())
        {
          for (final Control c : e.getValue())
          {
            wrap(lines,
                 INFO_RESULT_UTILS_END_TXN_RESULT_OP_CONTROL.get(e.getKey()),
                 prefix, maxWidth);
            formatResponseControl(lines, c, prefix + "     ", maxWidth);
          }
        }
      }
    }
    else if (result instanceof MultiUpdateExtendedResult)
    {
      final MultiUpdateExtendedResult multiUpdateResult =
           (MultiUpdateExtendedResult) result;

      final MultiUpdateChangesApplied changesApplied =
           multiUpdateResult.getChangesApplied();
      if (changesApplied != null)
      {
        wrap(lines,
             INFO_RESULT_UTILS_MULTI_UPDATE_CHANGES_APPLIED.get(
                  changesApplied.name()),
             prefix, maxWidth);
      }

      final List<ObjectPair<OperationType,LDAPResult>> multiUpdateResults =
           multiUpdateResult.getResults();
      if (multiUpdateResults != null)
      {
        for (final ObjectPair<OperationType,LDAPResult> p : multiUpdateResults)
        {
          wrap(lines,
               INFO_RESULT_UTILS_MULTI_UPDATE_RESULT_HEADER.get(
                    p.getFirst().name()),
               prefix, maxWidth);
          formatResult(lines, p.getSecond(), false, prefix + "     ", maxWidth);
        }
      }
    }
    else if (result instanceof PasswordModifyExtendedResult)
    {
      final PasswordModifyExtendedResult passwordModifyResult =
           (PasswordModifyExtendedResult) result;

      final String generatedPassword =
           passwordModifyResult.getGeneratedPassword();
      if (generatedPassword != null)
      {
        wrap(lines,
             INFO_RESULT_UTILS_PASSWORD_MODIFY_RESULT_GENERATED_PW.get(
                  generatedPassword),
             prefix, maxWidth);
      }
    }
    else if (result instanceof ExtendedResult)
    {
      final ExtendedResult extendedResult = (ExtendedResult) result;
      final String oid = ((ExtendedResult) result).getOID();
      if (oid != null)
      {
        wrap(lines, INFO_RESULT_UTILS_RESPONSE_EXTOP_OID.get(oid), prefix,
             maxWidth);
      }

      final ASN1OctetString value = extendedResult.getValue();
      if ((value != null) && (value.getValueLength() > 0))
      {
        wrap(lines, INFO_RESULT_UTILS_RESPONSE_EXTOP_RAW_VALUE_HEADER.get(),
             prefix, maxWidth);

        // We'll ignore the maximum width for this portion of the output.
        for (final String line :
             StaticUtils.stringToLines(
                  StaticUtils.toHexPlusASCII(value.getValue(), 0)))
        {
          lines.add(prefix + "     " + line);
        }
      }
    }


    // If there are any controls, then display them.  We'll interpret any
    // controls that we can, but will fall back to a general display for any
    // that we don't recognize or can't parse.
    final Control[] controls = result.getResponseControls();
    if (controls != null)
    {
      for (final Control c : controls)
      {
        formatResponseControl(lines, c, prefix, maxWidth);
      }
    }
  }



  /**
   * Updates the provided list with an LDIF representation of the provided
   * search result entry to the given list, preceded by comments about any
   * controls that may be included with the entry.
   *
   * @param  lines     The list to which the formatted representation will be
   *                   added.
   * @param  entry     The entry to be formatted.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   any comment prefix and indent.
   */
  public static void formatSearchResultEntry(@NotNull final List<String> lines,
                          @NotNull final SearchResultEntry entry,
                          final int maxWidth)
  {
    for (final Control c : entry.getControls())
    {
      formatResponseControl(lines, c, true, 0, maxWidth);
    }

    lines.addAll(Arrays.asList(entry.toLDIF(maxWidth)));
  }



  /**
   * Updates the provided with with a string representation of the provided
   * search result reference.  The information will be written as LDIF
   * comments, and will include any referral URLs contained in the reference, as
   * well as information about any associated controls.
   *
   * @param  lines      The list to which the formatted representation will be
   *                    added.
   * @param  reference  The search result reference to be formatted.
   * @param  maxWidth   The maximum length of each line in characters, including
   *                    any comment prefix and indent.
   */
  public static void formatSearchResultReference(
                          @NotNull final List<String> lines,
                          @NotNull final SearchResultReference reference,
                          final int maxWidth)
  {
    wrap(lines, INFO_RESULT_UTILS_SEARCH_REFERENCE_HEADER.get(), "# ",
         maxWidth);
    for (final String url : reference.getReferralURLs())
    {
      wrap(lines, INFO_RESULT_UTILS_REFERRAL_URL.get(url), "#      ", maxWidth);
    }

    for (final Control c : reference.getControls())
    {
      formatResponseControl(lines, c, "#      ", maxWidth);
    }
  }



  /**
   * Adds a multi-line string representation of the provided unsolicited
   * notification to the given list.
   *
   * @param  lines         The list to which the lines should be added.
   * @param  notification  The unsolicited notification to be formatted.
   * @param  comment       Indicates whether to prefix each line with an
   *                       octothorpe to indicate that it is a comment.
   * @param  indent        The number of spaces to indent each line.
   * @param  maxWidth      The maximum length of each line in characters,
   *                       including the comment prefix and indent.
   */
  public static void formatUnsolicitedNotification(
                          @NotNull final List<String> lines,
                          @NotNull final ExtendedResult notification,
                          final boolean comment, final int indent,
                          final int maxWidth)
  {
    final String prefix = createPrefix(comment, indent);
    final String indentPrefix = prefix + "     ";

    boolean includeRawValue = true;
    final String oid = notification.getOID();
    if (oid != null)
    {
      if (oid.equals(NoticeOfDisconnectionExtendedResult.
           NOTICE_OF_DISCONNECTION_RESULT_OID))
      {
        wrap(lines, INFO_RESULT_UTILS_NOTICE_OF_DISCONNECTION_HEADER.get(),
             prefix, maxWidth);
        wrap(lines, INFO_RESULT_UTILS_RESPONSE_EXTOP_OID.get(oid),
             indentPrefix, maxWidth);
      }
      else if (oid.equals(AbortedTransactionExtendedResult.
           ABORTED_TRANSACTION_RESULT_OID))
      {
        wrap(lines, INFO_RESULT_UTILS_ABORTED_TXN_HEADER.get(), prefix,
             maxWidth);
        wrap(lines, INFO_RESULT_UTILS_RESPONSE_EXTOP_OID.get(oid),
             indentPrefix, maxWidth);

        try
        {
          final AbortedTransactionExtendedResult r =
               new AbortedTransactionExtendedResult(notification);

          final String txnID;
          if (StaticUtils.isPrintableString(r.getTransactionID().getValue()))
          {
            txnID = r.getTransactionID().stringValue();
          }
          else
          {
            txnID = "0x" + StaticUtils.toHex(r.getTransactionID().getValue());
          }
          wrap(lines, INFO_RESULT_UTILS_TXN_ID_HEADER.get(txnID), indentPrefix,
               maxWidth);
          includeRawValue = false;
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
      else
      {
        wrap(lines, INFO_RESULT_UTILS_UNSOLICITED_NOTIFICATION_HEADER.get(),
             prefix, maxWidth);
        wrap(lines, INFO_RESULT_UTILS_RESPONSE_EXTOP_OID.get(oid),
             indentPrefix, maxWidth);
      }
    }
    else
    {
      wrap(lines, INFO_RESULT_UTILS_UNSOLICITED_NOTIFICATION_HEADER.get(),
           prefix, maxWidth);
    }


    wrap(lines,
         INFO_RESULT_UTILS_RESULT_CODE.get(
              String.valueOf(notification.getResultCode())),
         indentPrefix, maxWidth);

    final String diagnosticMessage = notification.getDiagnosticMessage();
    if (diagnosticMessage != null)
    {
      wrap(lines,
           INFO_RESULT_UTILS_DIAGNOSTIC_MESSAGE.get(diagnosticMessage),
           indentPrefix, maxWidth);
    }

    final String matchedDN = notification.getMatchedDN();
    if (matchedDN != null)
    {
      wrap(lines, INFO_RESULT_UTILS_MATCHED_DN.get(matchedDN), indentPrefix,
           maxWidth);
    }

    final String[] referralURLs = notification.getReferralURLs();
    if (referralURLs != null)
    {
      for (final String referralURL : referralURLs)
      {
        wrap(lines, INFO_RESULT_UTILS_REFERRAL_URL.get(referralURL),
             indentPrefix, maxWidth);
      }
    }

    if (includeRawValue)
    {
      final ASN1OctetString value = notification.getValue();
      if ((value != null) && (value.getValueLength() > 0))
      {
        wrap(lines, INFO_RESULT_UTILS_RESPONSE_EXTOP_RAW_VALUE_HEADER.get(),
             indentPrefix, maxWidth);

        // We'll ignore the maximum width for this portion of the output.
        for (final String line :
             StaticUtils.stringToLines(
                  StaticUtils.toHexPlusASCII(value.getValue(), 0)))
        {
          lines.add(prefix + "          " + line);
        }
      }
    }


    // If there are any controls, then display them.  We'll interpret any
    // controls that we can, but will fall back to a general display for any
    // that we don't recognize or can't parse.
    final Control[] controls = notification.getResponseControls();
    if (controls != null)
    {
      for (final Control c : controls)
      {
        formatResponseControl(lines, c, comment, indent+5, maxWidth);
      }
    }
  }



  /**
   * Adds a multi-line string representation of the provided result to the
   * given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  comment   Indicates whether to prefix each line with an octothorpe
   *                   to indicate that it is a comment.
   * @param  indent    The number of spaces to indent each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  public static void formatResponseControl(@NotNull final List<String> lines,
                                           @NotNull final Control c,
                                           final boolean comment,
                                           final int indent, final int maxWidth)
  {
    // Generate a prefix that will be used for every line.
    final StringBuilder buffer = new StringBuilder(indent + 2);
    if (comment)
    {
      buffer.append("# ");
    }
    for (int i=0; i < indent; i++)
    {
      buffer.append(' ');
    }
    final String prefix = buffer.toString();


    formatResponseControl(lines, c, prefix, maxWidth);
  }



  /**
   * Adds a multi-line string representation of the provided control to the
   * given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void formatResponseControl(@NotNull final List<String> lines,
                                            @NotNull final Control c,
                                            @NotNull final String prefix,
                                            final int maxWidth)
  {
    final String oid = c.getOID();
    if (oid.equals(AuthorizationIdentityResponseControl.
         AUTHORIZATION_IDENTITY_RESPONSE_OID))
    {
      addAuthorizationIdentityResponseControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(ContentSyncDoneControl.SYNC_DONE_OID))
    {
      addContentSyncDoneControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(ContentSyncStateControl.SYNC_STATE_OID))
    {
      addContentSyncStateControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(EntryChangeNotificationControl.
         ENTRY_CHANGE_NOTIFICATION_OID))
    {
      addEntryChangeNotificationControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(PasswordExpiredControl.PASSWORD_EXPIRED_OID))
    {
      addPasswordExpiredControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(PasswordExpiringControl.PASSWORD_EXPIRING_OID))
    {
      addPasswordExpiringControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(PostReadResponseControl.POST_READ_RESPONSE_OID))
    {
      addPostReadResponseControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(PreReadResponseControl.PRE_READ_RESPONSE_OID))
    {
      addPreReadResponseControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(ServerSideSortResponseControl.
         SERVER_SIDE_SORT_RESPONSE_OID))
    {
      addServerSideSortResponseControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(SimplePagedResultsControl.PAGED_RESULTS_OID))
    {
      addSimplePagedResultsControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(VirtualListViewResponseControl.
         VIRTUAL_LIST_VIEW_RESPONSE_OID))
    {
      addVirtualListViewResponseControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(AccountUsableResponseControl.
         ACCOUNT_USABLE_RESPONSE_OID))
    {
      addAccountUsableResponseControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(AssuredReplicationResponseControl.
         ASSURED_REPLICATION_RESPONSE_OID))
    {
      addAssuredReplicationResponseControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(GeneratePasswordResponseControl.
         GENERATE_PASSWORD_RESPONSE_OID))
    {
      addGeneratePasswordResponseControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(GetAuthorizationEntryResponseControl.
         GET_AUTHORIZATION_ENTRY_RESPONSE_OID))
    {
      addGetAuthorizationEntryResponseControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(GetBackendSetIDResponseControl.
         GET_BACKEND_SET_ID_RESPONSE_OID))
    {
      addGetBackendSetIDResponseControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(GetPasswordPolicyStateIssuesResponseControl.
         GET_PASSWORD_POLICY_STATE_ISSUES_RESPONSE_OID))
    {
      addGetPasswordPolicyStateIssuesResponseControl(lines, c, prefix,
           maxWidth);
    }
    else if (oid.equals(GetRecentLoginHistoryResponseControl.
         GET_RECENT_LOGIN_HISTORY_RESPONSE_OID))
    {
      addGetRecentLoginHistoryResponseControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(GetServerIDResponseControl.GET_SERVER_ID_RESPONSE_OID))
    {
      addGetServerIDResponseControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(GetUserResourceLimitsResponseControl.
         GET_USER_RESOURCE_LIMITS_RESPONSE_OID))
    {
      addGetUserResourceLimitsResponseControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(IntermediateClientResponseControl.
         INTERMEDIATE_CLIENT_RESPONSE_OID))
    {
      addIntermediateClientResponseControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(JoinResultControl.JOIN_RESULT_OID))
    {
      addJoinResultControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(MatchingEntryCountResponseControl.
         MATCHING_ENTRY_COUNT_RESPONSE_OID))
    {
      addMatchingEntryCountResponseControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(PasswordPolicyResponseControl.
         PASSWORD_POLICY_RESPONSE_OID))
    {
      addPasswordPolicyResponseControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(PasswordValidationDetailsResponseControl.
         PASSWORD_VALIDATION_DETAILS_RESPONSE_OID))
    {
      addPasswordValidationDetailsResponseControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(SoftDeleteResponseControl.SOFT_DELETE_RESPONSE_OID))
    {
      addSoftDeleteResponseControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(TransactionSettingsResponseControl.
         TRANSACTION_SETTINGS_RESPONSE_OID))
    {
      addTransactionSettingsResponseControl(lines, c, prefix, maxWidth);
    }
    else if (oid.equals(UniquenessResponseControl.UNIQUENESS_RESPONSE_OID))
    {
      addUniquenessResponseControl(lines, c, prefix, maxWidth);
    }
    else
    {
      addGenericResponseControl(lines, c, prefix, maxWidth);
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which will
   * be treated as a generic control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addGenericResponseControl(
               @NotNull final List<String> lines,
               @NotNull final Control c,
               @NotNull final String prefix,
               final int maxWidth)
  {
    wrap(lines, INFO_RESULT_UTILS_GENERIC_RESPONSE_CONTROL_HEADER.get(),
         prefix, maxWidth);
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         prefix + "     ", maxWidth);
    wrap(lines,
         INFO_RESULT_UTILS_RESPONSE_CONTROL_IS_CRITICAL.get(c.isCritical()),
         prefix + "     ", maxWidth);

    final ASN1OctetString value = c.getValue();
    if ((value != null) && (value.getValue().length > 0))
    {
      wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_RAW_VALUE_HEADER.get(),
           prefix + "     ", maxWidth);

      // We'll ignore the maximum width for this portion of the output.
      for (final String line :
           StaticUtils.stringToLines(
                StaticUtils.toHexPlusASCII(value.getValue(), 0)))
      {
        lines.add(prefix + "          " + line);
      }
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be an authorization identity response control, to the given
   * list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addAuthorizationIdentityResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix, final int maxWidth)
  {
    final AuthorizationIdentityResponseControl decoded;
    try
    {
      decoded = new AuthorizationIdentityResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_AUTHZ_ID_RESPONSE_HEADER.get(), prefix,
         maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);
    wrap(lines,
         INFO_RESULT_UTILS_AUTHZ_ID_RESPONSE_ID.get(
              decoded.getAuthorizationID()),
         indentPrefix, maxWidth);
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a content sync done control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addContentSyncDoneControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final ContentSyncDoneControl decoded;
    try
    {
      decoded = new ContentSyncDoneControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_CONTENT_SYNC_DONE_RESPONSE_HEADER.get(),
         prefix, maxWidth);
    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);
    wrap(lines,
         INFO_RESULT_UTILS_CONTENT_SYNC_DONE_REFRESH_DELETES.get(
              decoded.refreshDeletes()),
         indentPrefix, maxWidth);

    final ASN1OctetString cookie = decoded.getCookie();
    if (cookie != null)
    {
      wrap(lines, INFO_RESULT_UTILS_CONTENT_SYNC_DONE_COOKIE_HEADER.get(),
           indentPrefix, maxWidth);

      // We'll ignore the maximum width for this portion of the output.
      for (final String line :
           StaticUtils.stringToLines(
                StaticUtils.toHexPlusASCII(cookie.getValue(), 0)))
      {
        lines.add(indentPrefix + "     " + line);
      }
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a content sync state control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addContentSyncStateControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final ContentSyncStateControl decoded;
    try
    {
      decoded = new ContentSyncStateControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_CONTENT_SYNC_STATE_RESPONSE_HEADER.get(),
         prefix, maxWidth);
    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);
    wrap(lines,
         INFO_RESULT_UTILS_CONTENT_SYNC_STATE_ENTRY_UUID.get(
              decoded.getEntryUUID()),
         indentPrefix, maxWidth);
    wrap(lines,
         INFO_RESULT_UTILS_CONTENT_SYNC_STATE_NAME.get(
              decoded.getState().name()),
         indentPrefix, maxWidth);

    final ASN1OctetString cookie = decoded.getCookie();
    if (cookie != null)
    {
      wrap(lines, INFO_RESULT_UTILS_CONTENT_SYNC_STATE_COOKIE_HEADER.get(),
           indentPrefix, maxWidth);

      // We'll ignore the maximum width for this portion of the output.
      for (final String line :
           StaticUtils.stringToLines(
                StaticUtils.toHexPlusASCII(cookie.getValue(), 0)))
      {
        lines.add(indentPrefix + "     " + line);
      }
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be an entry change notification control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addEntryChangeNotificationControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final EntryChangeNotificationControl decoded;
    try
    {
      decoded = new EntryChangeNotificationControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_ECN_HEADER.get(), prefix, maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);

    final PersistentSearchChangeType changeType = decoded.getChangeType();
    if (changeType != null)
    {
      wrap(lines, INFO_RESULT_UTILS_ECN_CHANGE_TYPE.get(changeType.getName()),
           indentPrefix, maxWidth);
    }

    final long changeNumber = decoded.getChangeNumber();
    if (changeNumber >= 0L)
    {
      wrap(lines, INFO_RESULT_UTILS_ECN_CHANGE_NUMBER.get(changeNumber),
           indentPrefix, maxWidth);
    }

    final String previousDN = decoded.getPreviousDN();
    if (previousDN != null)
    {
      wrap(lines, INFO_RESULT_UTILS_ECN_PREVIOUS_DN.get(previousDN),
           indentPrefix, maxWidth);
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a password expired control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addPasswordExpiredControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final PasswordExpiredControl decoded;
    try
    {
      decoded = new PasswordExpiredControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_PASSWORD_EXPIRED_HEADER.get(), prefix,
         maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(decoded.getOID()),
         indentPrefix, maxWidth);
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a password expiring control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addPasswordExpiringControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final PasswordExpiringControl decoded;
    try
    {
      decoded = new PasswordExpiringControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_PASSWORD_EXPIRING_HEADER.get(), prefix,
         maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);

    final int secondsUntilExpiration = decoded.getSecondsUntilExpiration();
    if (secondsUntilExpiration >= 0)
    {
      wrap(lines,
           INFO_RESULT_UTILS_PASSWORD_EXPIRING_SECONDS_UNTIL_EXPIRATION.get(
                secondsUntilExpiration),
           indentPrefix, maxWidth);
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a post-read response control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addPostReadResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final PostReadResponseControl decoded;
    try
    {
      decoded = new PostReadResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_POST_READ_HEADER.get(), prefix, maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);
    wrap(lines, INFO_RESULT_UTILS_POST_READ_ENTRY_HEADER.get(c.getOID()),
         indentPrefix, maxWidth);
    addLDIF(lines, decoded.getEntry(), true, indentPrefix + "     ", maxWidth);
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a pre-read response control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addPreReadResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final PreReadResponseControl decoded;
    try
    {
      decoded = new PreReadResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_PRE_READ_HEADER.get(), prefix, maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);
    wrap(lines, INFO_RESULT_UTILS_PRE_READ_ENTRY_HEADER.get(c.getOID()),
         indentPrefix, maxWidth);
    addLDIF(lines, decoded.getEntry(), true, indentPrefix + "     ", maxWidth);
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a server-side sort response control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addServerSideSortResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final ServerSideSortResponseControl decoded;
    try
    {
      decoded = new ServerSideSortResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_SORT_HEADER.get(), prefix, maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);

    final ResultCode resultCode = decoded.getResultCode();
    if (resultCode != null)
    {
      wrap(lines,
           INFO_RESULT_UTILS_SORT_RESULT_CODE.get(String.valueOf(resultCode)),
           indentPrefix, maxWidth);
    }

    final String attributeName = decoded.getAttributeName();
    if (attributeName != null)
    {
      wrap(lines, INFO_RESULT_UTILS_SORT_ATTRIBUTE_NAME.get(attributeName),
           indentPrefix, maxWidth);
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a simple paged results control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addSimplePagedResultsControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final SimplePagedResultsControl decoded;
    try
    {
      decoded = new SimplePagedResultsControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_PAGED_RESULTS_HEADER.get(), prefix, maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);

    final int estimatedCount = decoded.getSize();
    if (estimatedCount >= 0)
    {
      wrap(lines, INFO_RESULT_UTILS_PAGED_RESULTS_COUNT.get(estimatedCount),
           indentPrefix, maxWidth);
    }

    final ASN1OctetString cookie = decoded.getCookie();
    if (cookie != null)
    {
      wrap(lines, INFO_RESULT_UTILS_PAGED_RESULTS_COOKIE_HEADER.get(),
           indentPrefix, maxWidth);

      // We'll ignore the maximum width for this portion of the output.
      for (final String line :
           StaticUtils.stringToLines(
                StaticUtils.toHexPlusASCII(cookie.getValue(), 0)))
      {
        lines.add(indentPrefix + "     " + line);
      }
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a virtual list view response control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addVirtualListViewResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final VirtualListViewResponseControl decoded;
    try
    {
      decoded = new VirtualListViewResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_VLV_HEADER.get(), prefix, maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);

    final ResultCode resultCode = decoded.getResultCode();
    if (resultCode != null)
    {
      wrap(lines,
           INFO_RESULT_UTILS_VLV_RESULT_CODE.get(String.valueOf(resultCode)),
           indentPrefix, maxWidth);
    }

    final int contentCount = decoded.getContentCount();
    if (contentCount >= 0)
    {
      wrap(lines, INFO_RESULT_UTILS_VLV_CONTENT_COUNT.get(contentCount),
           indentPrefix, maxWidth);
    }

    final int targetPosition = decoded.getTargetPosition();
    if (targetPosition >= 0)
    {
      wrap(lines, INFO_RESULT_UTILS_VLV_TARGET_POSITION.get(targetPosition),
           indentPrefix, maxWidth);
    }

    final ASN1OctetString contextID = decoded.getContextID();
    if (contextID != null)
    {
      wrap(lines, INFO_RESULT_UTILS_VLV_CONTEXT_ID_HEADER.get(),
           indentPrefix, maxWidth);

      // We'll ignore the maximum width for this portion of the output.
      for (final String line :
           StaticUtils.stringToLines(
                StaticUtils.toHexPlusASCII(contextID.getValue(), 0)))
      {
        lines.add(indentPrefix + "     " + line);
      }
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be an account usable response control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addAccountUsableResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final AccountUsableResponseControl decoded;
    try
    {
      decoded = new AccountUsableResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_ACCOUNT_USABLE_HEADER.get(), prefix,
         maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);
    wrap(lines,
         INFO_RESULT_UTILS_ACCOUNT_USABLE_IS_USABLE.get(decoded.isUsable()),
         indentPrefix, maxWidth);

    final List<String> unusableReasons = decoded.getUnusableReasons();
    if ((unusableReasons != null) && (! unusableReasons.isEmpty()))
    {
      wrap(lines,
           INFO_RESULT_UTILS_ACCOUNT_USABLE_UNUSABLE_REASONS_HEADER.get(),
           indentPrefix, maxWidth);
      for (final String reason : unusableReasons)
      {
        wrap(lines, reason, indentPrefix + "     ", maxWidth);
      }
    }

    wrap(lines,
         INFO_RESULT_UTILS_ACCOUNT_USABLE_PW_EXPIRED.get(
              decoded.passwordIsExpired()),
         indentPrefix, maxWidth);
    wrap(lines,
         INFO_RESULT_UTILS_ACCOUNT_USABLE_MUST_CHANGE_PW.get(
              decoded.mustChangePassword()),
         indentPrefix, maxWidth);
    wrap(lines,
         INFO_RESULT_UTILS_ACCOUNT_USABLE_IS_INACTIVE.get(decoded.isInactive()),
         indentPrefix, maxWidth);

    final int remainingGraceLogins = decoded.getRemainingGraceLogins();
    if (remainingGraceLogins >= 0)
    {
      wrap(lines,
           INFO_RESULT_UTILS_ACCOUNT_USABLE_REMAINING_GRACE.get(
                remainingGraceLogins),
           indentPrefix, maxWidth);
    }

    final int secondsUntilExpiration = decoded.getSecondsUntilExpiration();
    if (secondsUntilExpiration >= 0)
    {
      wrap(lines,
           INFO_RESULT_UTILS_ACCOUNT_USABLE_SECONDS_UNTIL_EXPIRATION.get(
                secondsUntilExpiration),
           indentPrefix, maxWidth);
    }

    final int secondsUntilUnlock = decoded.getSecondsUntilUnlock();
    if (secondsUntilUnlock >= 0)
    {
      wrap(lines,
           INFO_RESULT_UTILS_ACCOUNT_USABLE_SECONDS_UNTIL_UNLOCK.get(
                secondsUntilUnlock),
           indentPrefix, maxWidth);
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be an assured replication response control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addAssuredReplicationResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final AssuredReplicationResponseControl decoded;
    try
    {
      decoded = new AssuredReplicationResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_ASSURED_REPL_HEADER.get(), prefix, maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);

    final String csn = decoded.getCSN();
    if (csn != null)
    {
      wrap(lines, INFO_RESULT_UTILS_ASSURED_REPL_CSN.get(csn), indentPrefix,
           maxWidth);
    }

    final AssuredReplicationLocalLevel localLevel = decoded.getLocalLevel();
    if (localLevel != null)
    {
      wrap(lines,
           INFO_RESULT_UTILS_ASSURED_REPL_LOCAL_LEVEL.get(localLevel.name()),
           indentPrefix, maxWidth);
    }

    wrap(lines,
         INFO_RESULT_UTILS_ASSURED_REPL_LOCAL_SATISFIED.get(
              decoded.localAssuranceSatisfied()),
         indentPrefix, maxWidth);

    final String localMessage = decoded.getLocalAssuranceMessage();
    if (localMessage != null)
    {
      wrap(lines,
           INFO_RESULT_UTILS_ASSURED_REPL_LOCAL_MESSAGE.get(localMessage),
           indentPrefix, maxWidth);
    }

    final AssuredReplicationRemoteLevel remoteLevel = decoded.getRemoteLevel();
    if (remoteLevel != null)
    {
      wrap(lines,
           INFO_RESULT_UTILS_ASSURED_REPL_REMOTE_LEVEL.get(remoteLevel.name()),
           indentPrefix, maxWidth);
    }

    wrap(lines,
         INFO_RESULT_UTILS_ASSURED_REPL_REMOTE_SATISFIED.get(
              decoded.remoteAssuranceSatisfied()),
         indentPrefix, maxWidth);

    final String remoteMessage = decoded.getRemoteAssuranceMessage();
    if (remoteMessage != null)
    {
      wrap(lines,
           INFO_RESULT_UTILS_ASSURED_REPL_REMOTE_MESSAGE.get(remoteMessage),
           indentPrefix, maxWidth);
    }

    final List<AssuredReplicationServerResult> serverResults =
         decoded.getServerResults();
    if (serverResults != null)
    {
      for (final AssuredReplicationServerResult r : serverResults)
      {
        wrap(lines,
             INFO_RESULT_UTILS_ASSURED_REPL_SERVER_RESULT_HEADER.get(),
             indentPrefix, maxWidth);

        final AssuredReplicationServerResultCode rc = r.getResultCode();
        if (rc != null)
        {
          wrap(lines,
               INFO_RESULT_UTILS_ASSURED_REPL_SERVER_RESULT_CODE.get(rc.name()),
               indentPrefix + "     ", maxWidth);
        }

        final Short replicationServerID = r.getReplicationServerID();
        if (replicationServerID != null)
        {
          wrap(lines,
               INFO_RESULT_UTILS_ASSURED_REPL_SERVER_RESULT_REPL_SERVER_ID.get(
                    replicationServerID),
               indentPrefix + "     ", maxWidth);
        }

        final Short replicaID = r.getReplicaID();
        if (replicaID != null)
        {
          wrap(lines,
               INFO_RESULT_UTILS_ASSURED_REPL_SERVER_RESULT_REPL_ID.get(
                    replicaID),
               indentPrefix + "     ", maxWidth);
        }
      }
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a generate password response control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addGeneratePasswordResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final GeneratePasswordResponseControl decoded;
    try
    {
      decoded = new GeneratePasswordResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_GENERATE_PW_HEADER.get(), prefix,
         maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);
    wrap(lines,
         INFO_RESULT_UTILS_GENERATE_PW_PASSWORD.get(
              decoded.getGeneratedPasswordString()),
         indentPrefix, maxWidth);
    wrap(lines,
         INFO_RESULT_UTILS_GENERATE_PW_MUST_CHANGE.get(
              String.valueOf(decoded.mustChangePassword())),
         indentPrefix, maxWidth);

    if (decoded.getSecondsUntilExpiration() != null)
    {
      wrap(lines,
           INFO_RESULT_UTILS_GENERATE_PW_SECONDS_UNTIL_EXPIRATION.get(
                decoded.getSecondsUntilExpiration().longValue()),
           indentPrefix, maxWidth);
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a get authorization entry response control, to the given
   * list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addGetAuthorizationEntryResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final GetAuthorizationEntryResponseControl decoded;
    try
    {
      decoded = new GetAuthorizationEntryResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_GET_AUTHZ_ENTRY_HEADER.get(), prefix,
         maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);
    wrap(lines,
         INFO_RESULT_UTILS_GET_AUTHZ_ENTRY_IS_AUTHENTICATED.get(
              decoded.isAuthenticated()),
         indentPrefix, maxWidth);

    if (! decoded.isAuthenticated())
    {
      return;
    }

    wrap(lines,
         INFO_RESULT_UTILS_GET_AUTHZ_ENTRY_IDS_MATCH.get(
              decoded.identitiesMatch()),
         indentPrefix, maxWidth);

    final String authNID = decoded.getAuthNID();
    if (authNID != null)
    {
      wrap(lines, INFO_RESULT_UTILS_GET_AUTHZ_ENTRY_AUTHN_ID.get(authNID),
           indentPrefix, maxWidth);
    }

    final Entry authNEntry = decoded.getAuthNEntry();
    if (authNEntry != null)
    {
      wrap(lines, INFO_RESULT_UTILS_GET_AUTHZ_ENTRY_AUTHN_ENTRY_HEADER.get(),
           indentPrefix, maxWidth);
      addLDIF(lines, authNEntry, true, indentPrefix + "     ", maxWidth);
    }

    if (decoded.identitiesMatch())
    {
      return;
    }

    final String authZID = decoded.getAuthZID();
    if (authZID != null)
    {
      wrap(lines, INFO_RESULT_UTILS_GET_AUTHZ_ENTRY_AUTHZ_ID.get(authZID),
           indentPrefix, maxWidth);
    }

    final Entry authZEntry = decoded.getAuthZEntry();
    if (authZEntry != null)
    {
      wrap(lines, INFO_RESULT_UTILS_GET_AUTHZ_ENTRY_AUTHZ_ENTRY_HEADER.get(),
           indentPrefix, maxWidth);
      addLDIF(lines, authZEntry, true, indentPrefix + "     ", maxWidth);
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a get backend set ID response control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addGetBackendSetIDResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final GetBackendSetIDResponseControl decoded;
    try
    {
      decoded = new GetBackendSetIDResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_GET_BACKEND_SET_ID_HEADER.get(), prefix,
         maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);
    wrap(lines,
         INFO_RESULT_UTILS_GET_BACKEND_SET_ID_EB_RP_ID.get(
              decoded.getEntryBalancingRequestProcessorID()),
         indentPrefix, maxWidth);

    for (final String id : decoded.getBackendSetIDs())
    {
      wrap(lines, INFO_RESULT_UTILS_GET_BACKEND_SET_ID.get(id), indentPrefix,
           maxWidth);
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a get password policy state issues response control, to the
   * given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addGetPasswordPolicyStateIssuesResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final GetPasswordPolicyStateIssuesResponseControl decoded;
    try
    {
      decoded = new GetPasswordPolicyStateIssuesResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_GET_PW_STATE_ISSUES_HEADER.get(), prefix,
         maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);

    final String doubleIndentPrefix = indentPrefix + "     ";
    final AuthenticationFailureReason authFailureReason =
         decoded.getAuthenticationFailureReason();
    if (authFailureReason != null)
    {
      wrap(lines,
           INFO_RESULT_UTILS_GET_PW_STATE_ISSUES_FAILURE_REASON_HEADER.get(),
           indentPrefix, maxWidth);
      wrap(lines,
           INFO_RESULT_UTILS_GET_PW_STATE_ISSUES_FAILURE_TYPE.get(
                authFailureReason.getName()),
           doubleIndentPrefix, maxWidth);

      final String message = authFailureReason.getMessage();
      if (message != null)
      {
        wrap(lines,
             INFO_RESULT_UTILS_GET_PW_STATE_ISSUES_FAILURE_MESSAGE.get(message),
             doubleIndentPrefix, maxWidth);
      }
    }

    final List<PasswordPolicyStateAccountUsabilityError> errors =
         decoded.getErrors();
    if (errors != null)
    {
      for (final PasswordPolicyStateAccountUsabilityError e : errors)
      {
        wrap(lines, INFO_RESULT_UTILS_GET_PW_STATE_ISSUES_ERROR_HEADER.get(),
             indentPrefix, maxWidth);
        wrap(lines,
             INFO_RESULT_UTILS_GET_PW_STATE_ISSUES_ERROR_NAME.get(e.getName()),
             doubleIndentPrefix, maxWidth);

        final String message = e.getMessage();
        if (message != null)
        {
          wrap(lines,
               INFO_RESULT_UTILS_GET_PW_STATE_ISSUES_ERROR_MESSAGE.get(message),
               doubleIndentPrefix, maxWidth);
        }
      }
    }

    final List<PasswordPolicyStateAccountUsabilityWarning> warnings =
         decoded.getWarnings();
    if (warnings != null)
    {
      for (final PasswordPolicyStateAccountUsabilityWarning w : warnings)
      {
        wrap(lines, INFO_RESULT_UTILS_GET_PW_STATE_ISSUES_WARNING_HEADER.get(),
             indentPrefix, maxWidth);
        wrap(lines,
             INFO_RESULT_UTILS_GET_PW_STATE_ISSUES_WARNING_NAME.get(
                  w.getName()),
             doubleIndentPrefix, maxWidth);

        final String message = w.getMessage();
        if (message != null)
        {
          wrap(lines,
               INFO_RESULT_UTILS_GET_PW_STATE_ISSUES_WARNING_MESSAGE.get(
                    message),
               doubleIndentPrefix, maxWidth);
        }
      }
    }

    final List<PasswordPolicyStateAccountUsabilityNotice> notices =
         decoded.getNotices();
    if (notices != null)
    {
      for (final PasswordPolicyStateAccountUsabilityNotice n : notices)
      {
        wrap(lines, INFO_RESULT_UTILS_GET_PW_STATE_ISSUES_NOTICE_HEADER.get(),
             indentPrefix, maxWidth);
        wrap(lines,
             INFO_RESULT_UTILS_GET_PW_STATE_ISSUES_NOTICE_NAME.get(n.getName()),
             doubleIndentPrefix, maxWidth);

        final String message = n.getMessage();
        if (message != null)
        {
          wrap(lines,
               INFO_RESULT_UTILS_GET_PW_STATE_ISSUES_NOTICE_MESSAGE.get(
                    message),
               doubleIndentPrefix, maxWidth);
        }
      }
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a get recent login history response control, to the given
   * list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addGetRecentLoginHistoryResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final GetRecentLoginHistoryResponseControl decoded;
    try
    {
      decoded = new GetRecentLoginHistoryResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_GET_RECENT_LOGIN_HISTORY_HEADER.get(), prefix,
         maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);

    final RecentLoginHistory history = decoded.getRecentLoginHistory();
    if (history.getSuccessfulAttempts().isEmpty())
    {
      wrap(lines,
           INFO_RESULT_UTILS_GET_RECENT_LOGIN_HISTORY_NO_SUCCESSES.get(),
           indentPrefix, maxWidth);
    }

    for (final RecentLoginHistoryAttempt attempt :
         history.getSuccessfulAttempts())
    {
      wrap(lines,
           INFO_RESULT_UTILS_GET_RECENT_LOGIN_HISTORY_SUCCESS_HEADER.get(),
           indentPrefix, maxWidth);

      final String doubleIndentPrefix = indentPrefix + "     ";
      wrap(lines,
           INFO_RESULT_UTILS_GET_RECENT_LOGIN_HISTORY_TIMESTAMP.get(
                StaticUtils.encodeRFC3339Time(attempt.getTimestamp())),
           doubleIndentPrefix, maxWidth);
      wrap(lines,
           INFO_RESULT_UTILS_GET_RECENT_LOGIN_HISTORY_AUTH_METHOD.get(
                attempt.getAuthenticationMethod()),
           doubleIndentPrefix, maxWidth);

      final String clientIP = attempt.getClientIPAddress();
      if (clientIP != null)
      {
        wrap(lines,
             INFO_RESULT_UTILS_GET_RECENT_LOGIN_HISTORY_CLIENT_IP.get(clientIP),
             doubleIndentPrefix, maxWidth);
      }

      final Long additionalAttemptCount = attempt.getAdditionalAttemptCount();
      if (additionalAttemptCount != null)
      {
        wrap(lines,
             INFO_RESULT_UTILS_GET_RECENT_LOGIN_HISTORY_ADDITIONAL_COUNT.get(
                  additionalAttemptCount),
             doubleIndentPrefix, maxWidth);
      }
    }

    if (history.getFailedAttempts().isEmpty())
    {
      wrap(lines,
           INFO_RESULT_UTILS_GET_RECENT_LOGIN_HISTORY_NO_FAILURES.get(),
           indentPrefix, maxWidth);
    }

    for (final RecentLoginHistoryAttempt attempt :
         history.getFailedAttempts())
    {
      wrap(lines,
           INFO_RESULT_UTILS_GET_RECENT_LOGIN_HISTORY_FAILURE_HEADER.get(),
           indentPrefix, maxWidth);

      final String doubleIndentPrefix = indentPrefix + "     ";
      wrap(lines,
           INFO_RESULT_UTILS_GET_RECENT_LOGIN_HISTORY_TIMESTAMP.get(
                StaticUtils.encodeRFC3339Time(attempt.getTimestamp())),
           doubleIndentPrefix, maxWidth);
      wrap(lines,
           INFO_RESULT_UTILS_GET_RECENT_LOGIN_HISTORY_AUTH_METHOD.get(
                attempt.getAuthenticationMethod()),
           doubleIndentPrefix, maxWidth);

      final String clientIP = attempt.getClientIPAddress();
      if (clientIP != null)
      {
        wrap(lines,
             INFO_RESULT_UTILS_GET_RECENT_LOGIN_HISTORY_CLIENT_IP.get(clientIP),
             doubleIndentPrefix, maxWidth);
      }

      wrap(lines,
           INFO_RESULT_UTILS_GET_RECENT_LOGIN_HISTORY_FAILURE_REASON.get(
                attempt.getFailureReason()),
           doubleIndentPrefix, maxWidth);

      final Long additionalAttemptCount = attempt.getAdditionalAttemptCount();
      if (additionalAttemptCount != null)
      {
        wrap(lines,
             INFO_RESULT_UTILS_GET_RECENT_LOGIN_HISTORY_ADDITIONAL_COUNT.get(
                  additionalAttemptCount),
             doubleIndentPrefix, maxWidth);
      }
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a get server ID response control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addGetServerIDResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final GetServerIDResponseControl decoded;
    try
    {
      decoded = new GetServerIDResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }


    wrap(lines, INFO_RESULT_UTILS_GET_SERVER_ID_HEADER.get(), prefix,
         maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);
    wrap(lines, INFO_RESULT_UTILS_GET_SERVER_ID.get(decoded.getServerID()),
         indentPrefix, maxWidth);
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a get user resource limits response control, to the given
   * list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addGetUserResourceLimitsResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final GetUserResourceLimitsResponseControl decoded;
    try
    {
      decoded = new GetUserResourceLimitsResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_GET_USER_RLIM_HEADER.get(), prefix,
         maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);

    final Long sizeLimit = decoded.getSizeLimit();
    if (sizeLimit != null)
    {
      final String value;
      if (sizeLimit > 0L)
      {
        value = String.valueOf(sizeLimit);
      }
      else
      {
        value = INFO_RESULT_UTILS_GET_USER_RLIM_VALUE_UNLIMITED.get();
      }

      wrap(lines, INFO_RESULT_UTILS_GET_USER_RLIM_SIZE_LIMIT.get(value),
           indentPrefix, maxWidth);
    }

    final Long timeLimit = decoded.getTimeLimitSeconds();
    if (timeLimit != null)
    {
      final String value;
      if (timeLimit > 0L)
      {
        value = timeLimit + " " +
             INFO_RESULT_UTILS_GET_USER_RLIM_UNIT_SECONDS.get();
      }
      else
      {
        value = INFO_RESULT_UTILS_GET_USER_RLIM_VALUE_UNLIMITED.get();
      }

      wrap(lines, INFO_RESULT_UTILS_GET_USER_RLIM_TIME_LIMIT.get(value),
           indentPrefix, maxWidth);
    }

    final Long idleTimeLimit = decoded.getIdleTimeLimitSeconds();
    if (idleTimeLimit != null)
    {
      final String value;
      if (idleTimeLimit > 0L)
      {
        value = idleTimeLimit + " " +
             INFO_RESULT_UTILS_GET_USER_RLIM_UNIT_SECONDS.get();
      }
      else
      {
        value = INFO_RESULT_UTILS_GET_USER_RLIM_VALUE_UNLIMITED.get();
      }

      wrap(lines, INFO_RESULT_UTILS_GET_USER_RLIM_IDLE_TIME_LIMIT.get(value),
           indentPrefix, maxWidth);
    }

    final Long lookthroughLimit = decoded.getLookthroughLimit();
    if (lookthroughLimit != null)
    {
      final String value;
      if (lookthroughLimit > 0L)
      {
        value = String.valueOf(lookthroughLimit);
      }
      else
      {
        value = INFO_RESULT_UTILS_GET_USER_RLIM_VALUE_UNLIMITED.get();
      }

      wrap(lines, INFO_RESULT_UTILS_GET_USER_RLIM_LOOKTHROUGH_LIMIT.get(value),
           indentPrefix, maxWidth);
    }

    final String equivalentUserDN = decoded.getEquivalentAuthzUserDN();
    if (equivalentUserDN != null)
    {
      wrap(lines,
           INFO_RESULT_UTILS_GET_USER_RLIM_EQUIVALENT_AUTHZ_USER_DN.get(
                equivalentUserDN),
           indentPrefix, maxWidth);
    }

    final String ccpName = decoded.getClientConnectionPolicyName();
    if (ccpName != null)
    {
      wrap(lines, INFO_RESULT_UTILS_GET_USER_RLIM_CCP_NAME.get(ccpName),
           indentPrefix, maxWidth);
    }

    final String doubleIndentPrefix = indentPrefix + "     ";
    final List<String> groupDNs = decoded.getGroupDNs();
    if ((groupDNs != null) && (! groupDNs.isEmpty()))
    {
      wrap(lines, INFO_RESULT_UTILS_GET_USER_RLIM_GROUP_DNS_HEADER.get(),
           indentPrefix, maxWidth);
      for (final String groupDN : groupDNs)
      {
        wrap(lines, groupDN, doubleIndentPrefix, maxWidth);
      }
    }

    final List<String> privilegeNames = decoded.getPrivilegeNames();
    if ((privilegeNames != null) && (! privilegeNames.isEmpty()))
    {
      wrap(lines, INFO_RESULT_UTILS_GET_USER_RLIM_PRIVILEGES_HEADER.get(),
           indentPrefix, maxWidth);
      for (final String privilegeName : privilegeNames)
      {
        wrap(lines, privilegeName, doubleIndentPrefix, maxWidth);
      }
    }

    final List<Attribute> otherAttrs = decoded.getOtherAttributes();
    if ((otherAttrs != null) && (! otherAttrs.isEmpty()))
    {
      wrap(lines, INFO_RESULT_UTILS_GET_USER_RLIM_OTHER_ATTRIBUTES_HEADER.get(),
           indentPrefix, maxWidth);
      addLDIF(lines, new Entry("", otherAttrs), false, doubleIndentPrefix,
           maxWidth);
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be an intermediate client response control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addIntermediateClientResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final IntermediateClientResponseControl decoded;
    try
    {
      decoded = new IntermediateClientResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_INTERMEDIATE_CLIENT_HEADER.get(), prefix,
         maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);
    addIntermediateResponseValue(lines, decoded.getResponseValue(),
         indentPrefix, maxWidth);
  }



  /**
   * Adds a multi-line string representation of the provided intermediate
   * response value to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  v         The value to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addIntermediateResponseValue(
                           @NotNull final List<String> lines,
                           @NotNull final IntermediateClientResponseValue v,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final String address = v.getUpstreamServerAddress();
    if (address != null)
    {
      wrap(lines,
           INFO_RESULT_UTILS_INTERMEDIATE_CLIENT_UPSTREAM_ADDRESS.get(address),
           prefix, maxWidth);
    }

    final Boolean secure = v.upstreamServerSecure();
    if (secure != null)
    {
      wrap(lines,
           INFO_RESULT_UTILS_INTERMEDIATE_CLIENT_UPSTREAM_SECURE.get(
                String.valueOf(secure)),
           prefix, maxWidth);
    }

    final String serverName = v.getServerName();
    if (serverName != null)
    {
      wrap(lines,
           INFO_RESULT_UTILS_INTERMEDIATE_CLIENT_SERVER_NAME.get(serverName),
           prefix, maxWidth);
    }

    final String sessionID = v.getServerSessionID();
    if (sessionID != null)
    {
      wrap(lines,
           INFO_RESULT_UTILS_INTERMEDIATE_CLIENT_SESSION_ID.get(sessionID),
           prefix, maxWidth);
    }

    final String responseID = v.getServerResponseID();
    if (responseID != null)
    {
      wrap(lines,
           INFO_RESULT_UTILS_INTERMEDIATE_CLIENT_RESPONSE_ID.get(responseID),
           prefix, maxWidth);
    }

    final IntermediateClientResponseValue upstreamResponse =
         v.getUpstreamResponse();
    if (upstreamResponse != null)
    {
      wrap(lines,
           INFO_RESULT_UTILS_INTERMEDIATE_CLIENT_UPSTREAM_RESPONSE_HEADER.get(),
           prefix, maxWidth);
      addIntermediateResponseValue(lines, upstreamResponse, prefix + "     ",
           maxWidth);
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a join result control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addJoinResultControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final JoinResultControl decoded;
    try
    {
      decoded = new JoinResultControl(c.getOID(), c.isCritical(), c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_JOIN_HEADER.get(), prefix,
         maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);

    final ResultCode resultCode = decoded.getResultCode();
    if (resultCode != null)
    {
      wrap(lines,
           INFO_RESULT_UTILS_JOIN_RESULT_CODE.get(
                String.valueOf(resultCode)),
           indentPrefix, maxWidth);
    }

    final String diagnosticMessage = decoded.getDiagnosticMessage();
    if (diagnosticMessage != null)
    {
      wrap(lines,
           INFO_RESULT_UTILS_JOIN_DIAGNOSTIC_MESSAGE.get(diagnosticMessage),
           indentPrefix, maxWidth);
    }

    final String matchedDN = decoded.getMatchedDN();
    if (matchedDN != null)
    {
      wrap(lines, INFO_RESULT_UTILS_JOIN_MATCHED_DN.get(matchedDN),
           indentPrefix, maxWidth);
    }

    final List<String> referralURLs = decoded.getReferralURLs();
    if (referralURLs != null)
    {
      for (final String referralURL : referralURLs)
      {
        wrap(lines, INFO_RESULT_UTILS_JOIN_REFERRAL_URL.get(referralURL),
             indentPrefix, maxWidth);
      }
    }

    final List<JoinedEntry> joinedEntries = decoded.getJoinResults();
    if (joinedEntries != null)
    {
      for (final JoinedEntry e : joinedEntries)
      {
        addJoinedEntry(lines, e, indentPrefix, maxWidth);
      }
    }
  }



  /**
   * Adds a multi-line string representation of the provided joined entry to the
   * given list.
   *
   * @param  lines        The list to which the lines should be added.
   * @param  joinedEntry  The joined entry to be formatted.
   * @param  prefix       The prefix to use for each line.
   * @param  maxWidth     The maximum length of each line in characters,
   *                      including the comment prefix and indent.
   */
  private static void addJoinedEntry(
                           @NotNull final List<String> lines,
                           @NotNull final JoinedEntry joinedEntry,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    wrap(lines, INFO_RESULT_UTILS_JOINED_WITH_ENTRY_HEADER.get(), prefix,
         maxWidth);
    addLDIF(lines, joinedEntry, true, prefix + "     ", maxWidth);

    final List<JoinedEntry> nestedJoinResults =
         joinedEntry.getNestedJoinResults();
    if (nestedJoinResults != null)
    {
      for (final JoinedEntry e : nestedJoinResults)
      {
        addJoinedEntry(lines, e, prefix + "          ", maxWidth);
      }
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a matching entry count response control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addMatchingEntryCountResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final MatchingEntryCountResponseControl decoded;
    try
    {
      decoded = new MatchingEntryCountResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_MATCHING_ENTRY_COUNT_HEADER.get(), prefix,
         maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);

    switch (decoded.getCountType())
    {
      case EXAMINED_COUNT:
        wrap(lines, INFO_RESULT_UTILS_MATCHING_ENTRY_COUNT_TYPE_EXAMINED.get(),
             indentPrefix, maxWidth);
        wrap(lines,
             INFO_RESULT_UTILS_MATCHING_ENTRY_COUNT_VALUE.get(
                  decoded.getCountValue()),
             indentPrefix, maxWidth);
        break;

      case UNEXAMINED_COUNT:
        wrap(lines,
             INFO_RESULT_UTILS_MATCHING_ENTRY_COUNT_TYPE_UNEXAMINED.get(),
             indentPrefix, maxWidth);
        wrap(lines,
             INFO_RESULT_UTILS_MATCHING_ENTRY_COUNT_VALUE.get(
                  decoded.getCountValue()),
             indentPrefix, maxWidth);
        break;

      case UPPER_BOUND:
        wrap(lines,
             INFO_RESULT_UTILS_MATCHING_ENTRY_COUNT_TYPE_UPPER_BOUND.get(),
             indentPrefix, maxWidth);
        wrap(lines,
             INFO_RESULT_UTILS_MATCHING_ENTRY_COUNT_VALUE.get(
                  decoded.getCountValue()),
             indentPrefix, maxWidth);
        break;

      case UNKNOWN:
      default:
        wrap(lines, INFO_RESULT_UTILS_MATCHING_ENTRY_COUNT_TYPE_UNKNOWN.get(),
             indentPrefix, maxWidth);
        break;
    }

    wrap(lines,
         INFO_RESULT_UTILS_MATCHING_ENTRY_COUNT_INDEXED.get(
              decoded.searchIndexed()),
         indentPrefix, maxWidth);

    final List<String> debugInfo = decoded.getDebugInfo();
    if ((debugInfo != null) && (! debugInfo.isEmpty()))
    {
      wrap(lines, INFO_RESULT_UTILS_MATCHING_ENTRY_COUNT_DEBUG_HEADER.get(),
           indentPrefix, maxWidth);
      for (final String s : debugInfo)
      {
        wrap(lines, s, indentPrefix + "     ", maxWidth);
      }
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be password policy response control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addPasswordPolicyResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final PasswordPolicyResponseControl decoded;
    try
    {
      decoded = new PasswordPolicyResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_PW_POLICY_HEADER.get(), prefix, maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);

    final PasswordPolicyErrorType errorType = decoded.getErrorType();
    if (errorType == null)
    {
      wrap(lines, INFO_RESULT_UTILS_PW_POLICY_ERROR_TYPE_NONE.get(),
           indentPrefix, maxWidth);
    }
    else
    {
      wrap(lines,
           INFO_RESULT_UTILS_PW_POLICY_ERROR_TYPE.get(errorType.getName()),
           indentPrefix, maxWidth);
    }

    final PasswordPolicyWarningType warningType = decoded.getWarningType();
    if (warningType == null)
    {
      wrap(lines, INFO_RESULT_UTILS_PW_POLICY_WARNING_TYPE_NONE.get(),
           indentPrefix, maxWidth);
    }
    else
    {
      wrap(lines,
           INFO_RESULT_UTILS_PW_POLICY_WARNING_TYPE.get(warningType.getName()),
           indentPrefix, maxWidth);
      wrap(lines,
           INFO_RESULT_UTILS_PW_POLICY_WARNING_VALUE.get(
                decoded.getWarningValue()),
           indentPrefix, maxWidth);
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a password validation details response control, to the given
   * list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addPasswordValidationDetailsResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final PasswordValidationDetailsResponseControl decoded;
    try
    {
      decoded = new PasswordValidationDetailsResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_PW_VALIDATION_DETAILS_HEADER.get(), prefix,
         maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);

    switch (decoded.getResponseType())
    {
      case VALIDATION_DETAILS:
        wrap(lines,
             INFO_RESULT_UTILS_PW_VALIDATION_DETAILS_RESULT_TYPE_RESULT.get(),
             indentPrefix, maxWidth);

        final List<PasswordQualityRequirementValidationResult> results =
             decoded.getValidationResults();
        if (results != null)
        {
          for (final PasswordQualityRequirementValidationResult r : results)
          {
            wrap(lines,
                 INFO_RESULT_UTILS_PW_VALIDATION_DETAILS_PQR_HEADER.get(),
                 indentPrefix + "     ", maxWidth);

            final String tripleIndentPrefix = indentPrefix + "          ";
            final PasswordQualityRequirement pqr = r.getPasswordRequirement();

            final String description = pqr.getDescription();
            if (description != null)
            {
              wrap(lines,
                   INFO_RESULT_UTILS_PW_VALIDATION_DETAILS_PQR_DESC.get(
                        description),
                   tripleIndentPrefix, maxWidth);
            }

            final String clientSideType = pqr.getClientSideValidationType();
            if (clientSideType != null)
            {
              wrap(lines,
                   INFO_RESULT_UTILS_PW_VALIDATION_DETAILS_PQR_TYPE.get(
                        clientSideType),
                   tripleIndentPrefix, maxWidth);
            }

            final Map<String,String> properties =
                 pqr.getClientSideValidationProperties();
            if (properties != null)
            {
              for (final Map.Entry<String,String> e : properties.entrySet())
              {
                wrap(lines,
                     INFO_RESULT_UTILS_PW_VALIDATION_DETAILS_PQR_PROP.get(
                          e.getKey(), e.getValue()),
                     tripleIndentPrefix, maxWidth);
              }
            }

            wrap(lines,
                 INFO_RESULT_UTILS_PW_VALIDATION_DETAILS_PQR_SATISFIED.get(
                      r.requirementSatisfied()),
                 tripleIndentPrefix, maxWidth);

            final String additionalInfo = r.getAdditionalInfo();
            if (additionalInfo != null)
            {
              wrap(lines,
                   INFO_RESULT_UTILS_PW_VALIDATION_DETAILS_PQR_INFO.get(
                        additionalInfo),
                   tripleIndentPrefix, maxWidth);
            }
          }
        }
        break;
      case NO_PASSWORD_PROVIDED:
        wrap(lines,
             INFO_RESULT_UTILS_PW_VALIDATION_DETAILS_RESULT_TYPE_NO_PW.get(),
             indentPrefix, maxWidth);
        break;
      case MULTIPLE_PASSWORDS_PROVIDED:
        wrap(lines,
             INFO_RESULT_UTILS_PW_VALIDATION_DETAILS_RESULT_TYPE_MULTIPLE_PW.
                  get(),
             indentPrefix, maxWidth);
        break;
      case NO_VALIDATION_ATTEMPTED:
        wrap(lines,
             INFO_RESULT_UTILS_PW_VALIDATION_DETAILS_RESULT_TYPE_NO_VALIDATION.
                  get(),
             indentPrefix, maxWidth);
        break;
      default:
        wrap(lines,
             INFO_RESULT_UTILS_PW_VALIDATION_DETAILS_RESULT_TYPE_DEFAULT.get(
                  decoded.getResponseType().name()),
             indentPrefix, maxWidth);
        break;
    }

    wrap(lines,
         INFO_RESULT_UTILS_PW_VALIDATION_DETAILS_MISSING_CURRENT.get(
              decoded.missingCurrentPassword()),
         indentPrefix, maxWidth);
    wrap(lines,
         INFO_RESULT_UTILS_PW_VALIDATION_DETAILS_MUST_CHANGE.get(
              decoded.mustChangePassword()),
         indentPrefix, maxWidth);

    final Integer secondsUntilExpiration = decoded.getSecondsUntilExpiration();
    if (secondsUntilExpiration != null)
    {
      wrap(lines,
           INFO_RESULT_UTILS_PW_VALIDATION_DETAILS_SECONDS_TO_EXP.get(
                secondsUntilExpiration),
           indentPrefix, maxWidth);
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a soft delete response control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addSoftDeleteResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final SoftDeleteResponseControl decoded;
    try
    {
      decoded = new SoftDeleteResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_SOFT_DELETE_HEADER.get(), prefix, maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);

    final String dn = decoded.getSoftDeletedEntryDN();
    if (dn != null)
    {
      wrap(lines, INFO_RESULT_UTILS_SOFT_DELETED_DN.get(dn), indentPrefix,
           maxWidth);
    }
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a transaction settings response control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addTransactionSettingsResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final TransactionSettingsResponseControl decoded;
    try
    {
      decoded = new TransactionSettingsResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_TXN_SETTINGS_HEADER.get(), prefix,
         maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);
    wrap(lines,
         INFO_RESULT_UTILS_TXN_SETTINGS_NUM_CONFLICTS.get(
              decoded.getNumLockConflicts()),
         indentPrefix, maxWidth);
    wrap(lines,
         INFO_RESULT_UTILS_TXN_SETTINGS_BACKEND_LOCK_ACQUIRED.get(
              decoded.backendLockAcquired()),
         indentPrefix, maxWidth);
  }



  /**
   * Adds a multi-line string representation of the provided control, which is
   * expected to be a uniqueness response control, to the given list.
   *
   * @param  lines     The list to which the lines should be added.
   * @param  c         The control to be formatted.
   * @param  prefix    The prefix to use for each line.
   * @param  maxWidth  The maximum length of each line in characters, including
   *                   the comment prefix and indent.
   */
  private static void addUniquenessResponseControl(
                           @NotNull final List<String> lines,
                           @NotNull final Control c,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    final UniquenessResponseControl decoded;
    try
    {
      decoded = new UniquenessResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addGenericResponseControl(lines, c, prefix, maxWidth);
      return;
    }

    wrap(lines, INFO_RESULT_UTILS_UNIQUENESS_HEADER.get(), prefix, maxWidth);

    final String indentPrefix = prefix + "     ";
    wrap(lines, INFO_RESULT_UTILS_RESPONSE_CONTROL_OID.get(c.getOID()),
         indentPrefix, maxWidth);
    wrap(lines, INFO_RESULT_UTILS_UNIQUENESS_ID.get(decoded.getUniquenessID()),
         indentPrefix, maxWidth);

    final String preCommitStatus;
    if (decoded.getPreCommitValidationPassed() == null)
    {
      preCommitStatus =
           INFO_RESULT_UTILS_UNIQUENESS_STATUS_VALUE_NOT_ATTEMPTED.get();
    }
    else if (decoded.getPreCommitValidationPassed() == Boolean.TRUE)
    {
      preCommitStatus = INFO_RESULT_UTILS_UNIQUENESS_STATUS_VALUE_PASSED.get();
    }
    else
    {
      preCommitStatus = INFO_RESULT_UTILS_UNIQUENESS_STATUS_VALUE_FAILED.get();
    }
    wrap(lines,
         INFO_RESULT_UTILS_UNIQUENESS_PRE_COMMIT_STATUS.get(preCommitStatus),
         indentPrefix, maxWidth);

    final String postCommitStatus;
    if (decoded.getPostCommitValidationPassed() == null)
    {
      postCommitStatus =
           INFO_RESULT_UTILS_UNIQUENESS_STATUS_VALUE_NOT_ATTEMPTED.get();
    }
    else if (decoded.getPostCommitValidationPassed() == Boolean.TRUE)
    {
      postCommitStatus = INFO_RESULT_UTILS_UNIQUENESS_STATUS_VALUE_PASSED.get();
    }
    else
    {
      postCommitStatus = INFO_RESULT_UTILS_UNIQUENESS_STATUS_VALUE_FAILED.get();
    }
    wrap(lines,
         INFO_RESULT_UTILS_UNIQUENESS_POST_COMMIT_STATUS.get(postCommitStatus),
         indentPrefix, maxWidth);

    final String message = decoded.getValidationMessage();
    if (message != null)
    {
      wrap(lines, INFO_RESULT_UTILS_UNIQUENESS_MESSAGE.get(message),
           indentPrefix, maxWidth);
    }
  }



  /**
   * Creates a string that may be used as a prefix for all lines with the given
   * settings.
   *
   * @param  comment  Indicates whether to prefix each line with an octothorpe
   *                  to indicate that it is a comment.
   * @param  indent   The number of spaces to indent each line.
   *
   * @return  A string that may be used as a prefix for all lines with the given
   *          settings.
   */
  @NotNull()
  private static String createPrefix(final boolean comment, final int indent)
  {
    // Generate a prefix that will be used for every line.
    final StringBuilder buffer = new StringBuilder(indent + 2);
    if (comment)
    {
      buffer.append("# ");
    }
    for (int i=0; i < indent; i++)
    {
      buffer.append(' ');
    }
    return buffer.toString();
  }



  /**
   * Adds a wrapped version of the provided string to the given list.
   *
   * @param  lines     The list to which the wrapped lines should be added.
   * @param  s         The string to be wrapped.
   * @param  prefix    The prefix to use at the beginning of each line.
   * @param  maxWidth  The maximum length of each line in characters.
   */
  private static void wrap(@NotNull final List<String> lines,
                           @NotNull final String s,
                           @NotNull final String prefix,
                           final int maxWidth)
  {
    // If the maximum width is less than the prefix length + 20 characters, then
    // make it make that the new effective maximum width.
    final int minimumMaxWidth   = prefix.length() + 20;
    final int effectiveMaxWidth = Math.max(minimumMaxWidth, maxWidth);


    // If the prefix plus the provided string is within the maximum width, then
    // there's no need to do any wrapping.
    if ((prefix.length() + s.length()) <= effectiveMaxWidth)
    {
      lines.add(prefix + s);
      return;
    }


    // Wrap the provided string.  If it spans multiple lines, all lines except
    // the first will be indented an extra five spaces.
    final List<String> wrappedLines = StaticUtils.wrapLine(s,
         (maxWidth - prefix.length()),
         (maxWidth - prefix.length() - 5));



    // Add the wrapped lines to the given list.
    for (int i=0; i < wrappedLines.size(); i++)
    {
      if (i > 0)
      {
        lines.add(prefix + "     " + wrappedLines.get(i));
      }
      else
      {
        lines.add(prefix + wrappedLines.get(i));
      }
    }
  }



  /**
   * Adds the lines that comprise an LDIF representation of the provided entry
   * to the given list.
   *
   * @param  lines      The list to which the lines should be added.
   * @param  entry      The entry to be formatted.
   * @param  includeDN  Indicates whether to include the DN of the entry in the
   *                    resulting LDIF representation.
   * @param  prefix     The prefix to use at the beginning of each line.
   * @param  maxWidth   The maximum length of each line in characters.
   */
  private static void addLDIF(@NotNull final List<String> lines,
                              @NotNull final Entry entry,
                              final boolean includeDN,
                              @NotNull final String prefix,
                              final int maxWidth)
  {
    // Never use a wrap column that is less than 20 characters.
    final int wrapColumn = Math.max(maxWidth - prefix.length(), 20);

    if (includeDN)
    {
      for (final String s : entry.toLDIF(wrapColumn))
      {
        lines.add(prefix + s);
      }
    }
    else
    {
      final String[] ldifLinesWithDN;
      if (entry.getDN().length() > 10)
      {
        final Entry dup = entry.duplicate();
        dup.setDN("");
        ldifLinesWithDN = dup.toLDIF(wrapColumn);
      }
      else
      {
        ldifLinesWithDN = entry.toLDIF(wrapColumn);
      }

      for (int i=1; i < ldifLinesWithDN.length; i++)
      {
        lines.add(prefix + ldifLinesWithDN[i]);
      }
    }
  }
}
