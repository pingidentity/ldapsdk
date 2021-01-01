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
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.TreeSet;
import java.util.UUID;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityResponseControl;
import com.unboundid.ldap.sdk.controls.ContentSyncDoneControl;
import com.unboundid.ldap.sdk.controls.ContentSyncState;
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
            AssuredReplicationResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationServerResult;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationServerResultCode;
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
import com.unboundid.ldap.sdk.unboundidds.controls.
            PasswordValidationDetailsResponseType;
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
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for the result utils class.
 */
public final class ResultUtilsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the {@code formatResult} method with the provided information.
   *
   * @param  result    The result to be formatted.
   * @param  expected  The expected formatted representation of the result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="formatResultData")
  public void testFormatResult(final LDAPResult result,
                               final List<String> expected)
         throws Exception
  {
    final ArrayList<String> lines = new ArrayList<String>(expected.size());
    ResultUtils.formatResult(lines, result, true, true, 5, Integer.MAX_VALUE);
    assertEquals(lines, expected,
         "Expected:" + StaticUtils.EOL + toMultiLine(expected) + "Got:" +
              StaticUtils.EOL + toMultiLine(lines));

    assertNotNull(ResultUtils.formatResult(new LDAPException(result), true, 0,
         40));
  }



  /**
   * Retrieves a set of data for testing the {@code formatResult} method.
   *
   * @return  The test data.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="formatResultData")
  public Iterator<Object[]> getFormatResultData()
         throws Exception
  {
    final LinkedList<Object[]> resultList = new LinkedList<Object[]>();


    // A simple success result.
    final String txnNoteLine = "#      NOTE:  No changes will actually be " +
         "applied to the server until the transaction is committed.";
    resultList.add(
         new Object[]
         {
           new LDAPResult(-1, ResultCode.SUCCESS),
           Arrays.asList(
                "#      Result Code:  0 (success)",
                txnNoteLine)
         });


    // A failure result with a single referral URL and a single control .
    final String[] singleReferralURL =
    {
      "ldap://ds.example.com:389/dc=example,dc=com"
    };
    final Control[] singleResponseControl =
    {
      new Control("1.2.3.4")
    };
    resultList.add(
         new Object[]
         {
           new LDAPResult(-1, ResultCode.OTHER, "Something went wrong",
                "dc=example,dc=com", singleReferralURL, singleResponseControl),
           Arrays.asList(
                "#      Result Code:  80 (other)",
                "#      Diagnostic Message:  Something went wrong",
                "#      Matched DN:  dc=example,dc=com",
                "#      Referral URL:  " +
                     "ldap://ds.example.com:389/dc=example,dc=com",
                "#      Response Control:",
                "#           OID:  1.2.3.4",
                "#           Is Critical:  false")
         });


    // A failure result with multiple referral URLs and multiple controls.
    final String[] multipleReferralURLs =
    {
      "ldap://ds1.example.com:389/dc=example,dc=com",
      "ldap://ds2.example.com:389/dc=example,dc=com"
    };
    final Control[] multipleResponseControls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString("control value"))
    };
    resultList.add(
         new Object[]
         {
           new LDAPResult(-1, ResultCode.OTHER, "Something went wrong",
                "dc=example,dc=com", multipleReferralURLs,
                multipleResponseControls),
           Arrays.asList(
                "#      Result Code:  80 (other)",
                "#      Diagnostic Message:  Something went wrong",
                "#      Matched DN:  dc=example,dc=com",
                "#      Referral URL:  " +
                     "ldap://ds1.example.com:389/dc=example,dc=com",
                "#      Referral URL:  " +
                     "ldap://ds2.example.com:389/dc=example,dc=com",
                "#      Response Control:",
                "#           OID:  1.2.3.4",
                "#           Is Critical:  false",
                "#      Response Control:",
                "#           OID:  1.2.3.5",
                "#           Is Critical:  true",
                "#           Raw Value:",
                "#                63 6f 6e 74 72 6f 6c 20 76 61 6c 75 " +
                     "65            control value")
         });


    // A successful start transaction extended result with a printable
    // transaction ID.
    resultList.add(
         new Object[]
         {
           new StartTransactionExtendedResult(2, ResultCode.SUCCESS, null, null,
                null, new ASN1OctetString("txnID"), null),
           Arrays.asList(
                "#      Result Code:  0 (success)",
                txnNoteLine,
                "#      Start Transaction Extended Result Transaction ID:  " +
                     "txnID")
         });


    // A successful start transaction extended result with a non-printable
    // transaction ID.
    resultList.add(
         new Object[]
         {
           new StartTransactionExtendedResult(2, ResultCode.SUCCESS, null, null,
                null, new ASN1OctetString(new byte[] { 0x01, 0x23, 0x45 }),
                null),
           Arrays.asList(
                "#      Result Code:  0 (success)",
                txnNoteLine,
                "#      Start Transaction Extended Result Transaction ID:  " +
                     "0x012345")
         });


    // A successful end transaction extended result.
    final LinkedHashMap<Integer,Control[]> opResponseControls =
         new LinkedHashMap<Integer,Control[]>(2);
    opResponseControls.put(3,
         new Control[]
         {
           new Control("1.2.3.4")
         });
    opResponseControls.put(4,
         new Control[]
         {
           new Control("1.2.3.4"),
           new Control("1.2.3.5", true, new ASN1OctetString("control value"))
         });
    resultList.add(
         new Object[]
         {
           new EndTransactionExtendedResult(5, ResultCode.SUCCESS, null, null,
                null, null, opResponseControls, null),
           Arrays.asList(
                "#      Result Code:  0 (success)",
                txnNoteLine,
                "#      End Transaction Extended Result Response Control for " +
                     "Message ID 3:",
                "#           Response Control:",
                "#                OID:  1.2.3.4",
                "#                Is Critical:  false",
                "#      End Transaction Extended Result Response Control for " +
                     "Message ID 4:",
                "#           Response Control:",
                "#                OID:  1.2.3.4",
                "#                Is Critical:  false",
                "#      End Transaction Extended Result Response Control for " +
                     "Message ID 4:",
                "#           Response Control:",
                "#                OID:  1.2.3.5",
                "#                Is Critical:  true",
                "#                Raw Value:",
                "#                     63 6f 6e 74 72 6f 6c 20 76 61 6c 75 " +
                     "65            control value")
         });


    // A failed end transaction extended result.
    resultList.add(
         new Object[]
         {
           new EndTransactionExtendedResult(5, ResultCode.OTHER,
                "One of the operations failed", null,
                null, 3, null, null),
           Arrays.asList(
                "#      Result Code:  80 (other)",
                "#      Diagnostic Message:  One of the operations failed",
                "#      End Transaction Extended Result Failed Operation " +
                     "Message ID:  3")
         });


    // A successful multi-update extended result.
    final ArrayList<ObjectPair<OperationType,LDAPResult>> opResults =
         new ArrayList<ObjectPair<OperationType,LDAPResult>>(2);
    opResults.add(new ObjectPair<OperationType,LDAPResult>(OperationType.ADD,
         new LDAPResult(3, ResultCode.SUCCESS)));
    opResults.add(new ObjectPair<OperationType,LDAPResult>(OperationType.DELETE,
         new LDAPResult(4, ResultCode.SUCCESS)));
    opResults.add(new ObjectPair<OperationType,LDAPResult>(OperationType.MODIFY,
         new LDAPResult(5, ResultCode.SUCCESS)));
    opResults.add(new ObjectPair<OperationType,LDAPResult>(
         OperationType.MODIFY_DN, new LDAPResult(6, ResultCode.SUCCESS)));
    resultList.add(
         new Object[]
         {
           new MultiUpdateExtendedResult(7, ResultCode.SUCCESS, null, null,
                null, MultiUpdateChangesApplied.ALL, opResults),
           Arrays.asList(
                "#      Result Code:  0 (success)",
                txnNoteLine,
                "#      Multi-Update Changes Applied:  ALL",
                "#      Multi-Update ADD Operation Result:",
                "#           Result Code:  0 (success)",
                "#      Multi-Update DELETE Operation Result:",
                "#           Result Code:  0 (success)",
                "#      Multi-Update MODIFY Operation Result:",
                "#           Result Code:  0 (success)",
                "#      Multi-Update MODIFY_DN Operation Result:",
                "#           Result Code:  0 (success)")
         });


    // A successful password modify extended result.
    resultList.add(
         new Object[]
         {
           new PasswordModifyExtendedResult(1, ResultCode.SUCCESS, null, null,
                null, new ASN1OctetString("newPassword"), null),
           Arrays.asList(
                "#      Result Code:  0 (success)",
                txnNoteLine,
                "#      Password Modify Extended Result Generated Password:  " +
                     "newPassword")
         });


    // A successful generic extended result.
    resultList.add(
         new Object[]
         {
           new ExtendedResult(1, ResultCode.SUCCESS, null, null, null,
                "1.2.3.4", new ASN1OctetString("extended operation value"),
                null),
           Arrays.asList(
                "#      Result Code:  0 (success)",
                txnNoteLine,
                "#      Extended Result OID:  1.2.3.4",
                "#      Extended Result Raw Value:",
                "#           65 78 74 65 6e 64 65 64 20 6f 70 65 72 61 74 " +
                     "69   extended operati",
                "#           6f 6e 20 76 61 6c 75 " +
                     "65                           on value")
         });


    return resultList.iterator();
  }



  /**
   * Tests the {@code formatUnsolicitedNotification} method with the provided
   * information.
   *
   * @param  notification  The unsolicited notification to be formatted.
   * @param  expected      The expected formatted representation of the
   *                       notification.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="formatUnsolicitedNotificationData")
  public void testFormatResult(final ExtendedResult notification,
                               final List<String> expected)
         throws Exception
  {
    final ArrayList<String> lines = new ArrayList<String>(expected.size());
    ResultUtils.formatUnsolicitedNotification(lines, notification, true, 5,
         Integer.MAX_VALUE);
    assertEquals(lines, expected,
         "Expected:" + StaticUtils.EOL + toMultiLine(expected) + "Got:" +
              StaticUtils.EOL + toMultiLine(lines));
  }



  /**
   * Retrieves a set of data for testing the
   * {@code formatUnsolicitedNotification} method.
   *
   * @return  The test data.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="formatUnsolicitedNotificationData")
  public Iterator<Object[]> getFormatUnsolicitedNotificationData()
         throws Exception
  {
    final LinkedList<Object[]> resultList = new LinkedList<Object[]>();


    // A notice of disconnection.
    resultList.add(
         new Object[]
         {
           new NoticeOfDisconnectionExtendedResult(ResultCode.SERVER_DOWN,
                "The server is shutting down."),
           Arrays.asList(
                "#      Notice of Disconnection Unsolicited Notification",
                "#           Extended Result OID:  1.3.6.1.4.1.1466.20036",
                "#           Result Code:  81 (server down)",
                "#           Diagnostic Message:  The server is shutting down.")
         });


    // An aborted transaction with a printable transaction ID.
    resultList.add(
         new Object[]
         {
           new AbortedTransactionExtendedResult(new ASN1OctetString("txnID"),
                ResultCode.OTHER, "The transaction was active for too long.",
                null, null, null),
           Arrays.asList(
                "#      Aborted Transaction Unsolicited Notification",
                "#           Extended Result OID:  1.3.6.1.1.21.4",
                "#           Transaction ID:  txnID",
                "#           Result Code:  80 (other)",
                "#           Diagnostic Message:  The transaction was active " +
                     "for too long.")
         });


    // An aborted transaction with a non-printable transaction ID.
    resultList.add(
         new Object[]
         {
           new AbortedTransactionExtendedResult(
                new ASN1OctetString(new byte[] { 0x01, 0x23, 0x45 }),
                ResultCode.OTHER, "The transaction was active for too long.",
                null, null, null),
           Arrays.asList(
                "#      Aborted Transaction Unsolicited Notification",
                "#           Extended Result OID:  1.3.6.1.1.21.4",
                "#           Transaction ID:  0x012345",
                "#           Result Code:  80 (other)",
                "#           Diagnostic Message:  The transaction was active " +
                     "for too long.")
         });


    // A generic unsolicited notification with neither an OID nor a value but
    // with all other elements.
    final String[] singleReferralURL =
    {
      "ldap://ds.example.com:389/dc=example,dc=com"
    };
    final Control[] singleResponseControl =
    {
      new Control("1.2.3.4")
    };
    resultList.add(
         new Object[]
         {
           new ExtendedResult(0, ResultCode.SUCCESS, "diag",
                "dc=example,dc=com", singleReferralURL, null, null,
                singleResponseControl),
           Arrays.asList(
                "#      Unsolicited Notification",
                "#           Result Code:  0 (success)",
                "#           Diagnostic Message:  diag",
                "#           Matched DN:  dc=example,dc=com",
                "#           Referral URL:  " +
                     "ldap://ds.example.com:389/dc=example,dc=com",
                "#           Response Control:",
                "#                OID:  1.2.3.4",
                "#                Is Critical:  false")
         });


    // A generic unsolicited notification with all elements.
    final String[] multipleReferralURLs =
    {
      "ldap://ds1.example.com:389/dc=example,dc=com",
      "ldap://ds2.example.com:389/dc=example,dc=com"
    };
    final Control[] multipleResponseControls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString("control value"))
    };
    resultList.add(
         new Object[]
         {
           new ExtendedResult(0, ResultCode.SUCCESS, "diag",
                "dc=example,dc=com", multipleReferralURLs, "5.6.7.8",
                new ASN1OctetString("extended operation value"),
                multipleResponseControls),
           Arrays.asList(
                "#      Unsolicited Notification",
                "#           Extended Result OID:  5.6.7.8",
                "#           Result Code:  0 (success)",
                "#           Diagnostic Message:  diag",
                "#           Matched DN:  dc=example,dc=com",
                "#           Referral URL:  " +
                     "ldap://ds1.example.com:389/dc=example,dc=com",
                "#           Referral URL:  " +
                     "ldap://ds2.example.com:389/dc=example,dc=com",
                "#           Extended Result Raw Value:",
                "#                65 78 74 65 6e 64 65 64 20 6f 70 65 72 61 " +
                     "74 69   extended operati",
                "#                6f 6e 20 76 61 6c 75 " +
                     "65                           on value",
                "#           Response Control:",
                "#                OID:  1.2.3.4",
                "#                Is Critical:  false",
                "#           Response Control:",
                "#                OID:  1.2.3.5",
                "#                Is Critical:  true",
                "#                Raw Value:",
                "#                     63 6f 6e 74 72 6f 6c 20 76 61 6c 75 " +
                     "65            control value")
         });


    return resultList.iterator();
  }



  /**
   * Tests the {@code formatResponseControl} method with the provided
   * information.
   *
   * @param  control   The control to be formatted.
   * @param  expected  The expected formatted representation of the control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="formatResponseControlData")
  public void testFormatResponseControl(final Control control,
                                        final List<String> expected)
         throws Exception
  {
    final ArrayList<String> lines = new ArrayList<String>(expected.size());
    ResultUtils.formatResponseControl(lines, control, true, 5,
         Integer.MAX_VALUE);
    assertEquals(lines, expected,
         "Expected:" + StaticUtils.EOL + toMultiLine(expected) + "Got:" +
              StaticUtils.EOL + toMultiLine(lines));
  }



  /**
   * Retrieves a set of data for testing the {@code formatResponseControl}
   * method.
   *
   * @return  The test data.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="formatResponseControlData")
  public Iterator<Object[]> getFormatResponseControlData()
         throws Exception
  {
    final LinkedList<Object[]> resultList = new LinkedList<Object[]>();


    // A generic response control with no value.
    resultList.add(
         new Object[]
         {
           new Control("1.2.3.4"),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  1.2.3.4",
                "#           Is Critical:  false")
         });


    // A generic response control with a value.
    resultList.add(
         new Object[]
         {
           new Control("1.2.3.4", true, new ASN1OctetString("control value")),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  1.2.3.4",
                "#           Is Critical:  true",
                "#           Raw Value:",
                "#                63 6f 6e 74 72 6f 6c 20 76 61 6c 75 " +
                     "65            control value")
         });


    // A valid authorization identity response control.
    resultList.add(
         new Object[]
         {
           new AuthorizationIdentityResponseControl("u:test.user"),
           Arrays.asList(
                "#      Authorization Identity Response Control:",
                "#           OID:  " + AuthorizationIdentityResponseControl.
                     AUTHORIZATION_IDENTITY_RESPONSE_OID,
                "#           Authorization ID:  u:test.user")
         });


    // An invalid authorization identity response control.
    resultList.add(
         new Object[]
         {
           new Control(
                AuthorizationIdentityResponseControl.
                     AUTHORIZATION_IDENTITY_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " + AuthorizationIdentityResponseControl.
                     AUTHORIZATION_IDENTITY_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid content synchronization done response control.
    resultList.add(
         new Object[]
         {
           new ContentSyncDoneControl(new ASN1OctetString("cookie"), true),
           Arrays.asList(
                "#      Content Synchronization Done Response Control:",
                "#           OID:  " + ContentSyncDoneControl.SYNC_DONE_OID,
                "#           Refresh Deletes:  true",
                "#           Cookie Data:",
                "#                63 6f 6f 6b 69 " +
                     "65                                 cookie")
         });


    // An invalid content synchronization done response control.
    resultList.add(
         new Object[]
         {
           new Control(ContentSyncDoneControl.SYNC_DONE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " + ContentSyncDoneControl.SYNC_DONE_OID,
                "#           Is Critical:  false")
         });


    // A valid content synchronization state response control.
    final UUID uuid = UUID.randomUUID();
    resultList.add(
         new Object[]
         {
           new ContentSyncStateControl(ContentSyncState.MODIFY, uuid,
                new ASN1OctetString("cookie")),
           Arrays.asList(
                "#      Content Synchronization State Response Control:",
                "#           OID:  " + ContentSyncStateControl.SYNC_STATE_OID,
                "#           Entry UUID:  " + uuid.toString(),
                "#           Synchronization State:  MODIFY",
                "#           Cookie Data:",
                "#                63 6f 6f 6b 69 " +
                     "65                                 cookie")
         });


    // An invalid content synchronization state response control.
    resultList.add(
         new Object[]
         {
           new Control(ContentSyncStateControl.SYNC_STATE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " + ContentSyncStateControl.SYNC_STATE_OID,
                "#           Is Critical:  false")
         });


    // A valid entry change notification control.
    resultList.add(
         new Object[]
         {
           new EntryChangeNotificationControl(
                PersistentSearchChangeType.MODIFY_DN,
                "ou=People,dc=example,dc=com", 123456789L),
           Arrays.asList(
                "#      Entry Change Notification Control:",
                "#           OID:  " + EntryChangeNotificationControl.
                     ENTRY_CHANGE_NOTIFICATION_OID,
                "#           Change Type:  moddn",
                "#           Change Number:  123456789",
                "#           Previous DN:  ou=People,dc=example,dc=com")
         });


    // An invalid entry change notification control.
    resultList.add(
         new Object[]
         {
           new Control(EntryChangeNotificationControl.
                ENTRY_CHANGE_NOTIFICATION_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " + EntryChangeNotificationControl.
                     ENTRY_CHANGE_NOTIFICATION_OID,
                "#           Is Critical:  false")
         });


    // A valid password expired control.
    resultList.add(
         new Object[]
         {
           new PasswordExpiredControl(),
           Arrays.asList(
                "#      Password Expired Response Control:",
                "#           OID:  " +
                     PasswordExpiredControl.PASSWORD_EXPIRED_OID)
         });


    // An invalid password expired control.
    resultList.add(
         new Object[]
         {
           new Control(PasswordExpiredControl.PASSWORD_EXPIRED_OID, false,
                new ASN1OctetString("control value")),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " +
                     PasswordExpiredControl.PASSWORD_EXPIRED_OID,
                "#           Is Critical:  false",
                "#           Raw Value:",
                "#                63 6f 6e 74 72 6f 6c 20 76 61 6c 75 " +
                     "65            control value")
         });


    // A valid password expiring control.
    resultList.add(
         new Object[]
         {
           new PasswordExpiringControl(12345),
           Arrays.asList(
                "#      Password Expiring Response Control:",
                "#           OID:  " +
                     PasswordExpiringControl.PASSWORD_EXPIRING_OID,
                "#           Seconds Until Expiration:  12345")
         });


    // An invalid password expiring control.
    resultList.add(
         new Object[]
         {
           new Control(PasswordExpiringControl.PASSWORD_EXPIRING_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " +
                     PasswordExpiringControl.PASSWORD_EXPIRING_OID,
                "#           Is Critical:  false")
         });


    // A valid post-read response control.
    resultList.add(
         new Object[]
         {
           new PostReadResponseControl(new ReadOnlyEntry(
                "dn: dc=example,dc=com",
                "objectClass: top",
                "objectClass: domain",
                "dc: example")),
           Arrays.asList(
                "#      Post-Read Response Control:",
                "#           OID:  " +
                     PostReadResponseControl.POST_READ_RESPONSE_OID,
                "#           Post-Read Entry:",
                "#                dn: dc=example,dc=com",
                "#                objectClass: top",
                "#                objectClass: domain",
                "#                dc: example")
         });


    // An invalid post-read response control.
    resultList.add(
         new Object[]
         {
           new Control(PostReadResponseControl.POST_READ_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " +
                     PostReadResponseControl.POST_READ_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid pre-read response control.
    resultList.add(
         new Object[]
         {
           new PreReadResponseControl(new ReadOnlyEntry(
                "dn: dc=example,dc=com",
                "objectClass: top",
                "objectClass: domain",
                "dc: example")),
           Arrays.asList(
                "#      Pre-Read Response Control:",
                "#           OID:  " +
                     PreReadResponseControl.PRE_READ_RESPONSE_OID,
                "#           Pre-Read Entry:",
                "#                dn: dc=example,dc=com",
                "#                objectClass: top",
                "#                objectClass: domain",
                "#                dc: example")
         });


    // An invalid pre-read response control.
    resultList.add(
         new Object[]
         {
           new Control(PreReadResponseControl.PRE_READ_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " +
                     PreReadResponseControl.PRE_READ_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid server-side sort response control.
    resultList.add(
         new Object[]
         {
           new ServerSideSortResponseControl(
                ResultCode.INVALID_ATTRIBUTE_SYNTAX, "objectClass", false),
           Arrays.asList(
                "#      Server-Side Sort Response Control:",
                "#           OID:  " + ServerSideSortResponseControl.
                     SERVER_SIDE_SORT_RESPONSE_OID,
                "#           Result Code:  21 (invalid attribute syntax)",
                "#           Attribute Name:  objectClass")
         });


    // An invalid server-side sort response control.
    resultList.add(
         new Object[]
         {
           new Control(ServerSideSortResponseControl.
                SERVER_SIDE_SORT_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " + ServerSideSortResponseControl.
                     SERVER_SIDE_SORT_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid simple paged results response control.
    resultList.add(
         new Object[]
         {
           new SimplePagedResultsControl(12345, new ASN1OctetString("cookie")),
           Arrays.asList(
                "#      Simple Paged Results Response Control:",
                "#           OID:  " +
                     SimplePagedResultsControl.PAGED_RESULTS_OID,
                "#           Estimated Total Result Set Size:  12345",
                "#           Cookie Data:",
                "#                63 6f 6f 6b 69 " +
                     "65                                 cookie")
         });


    // An invalid simple paged results response control.
    resultList.add(
         new Object[]
         {
           new Control(SimplePagedResultsControl.PAGED_RESULTS_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " +
                     SimplePagedResultsControl.PAGED_RESULTS_OID,
                "#           Is Critical:  false")
         });


    // A valid virtual list view response control.
    resultList.add(
         new Object[]
         {
           new VirtualListViewResponseControl(12345, 67890, ResultCode.SUCCESS,
                new ASN1OctetString("cookie")),
           Arrays.asList(
                "#      Virtual List View Response Control:",
                "#           OID:  " + VirtualListViewResponseControl.
                     VIRTUAL_LIST_VIEW_RESPONSE_OID,
                "#           Result Code:  0 (success)",
                "#           Estimated Content Count:  67890",
                "#           Target Position:  12345",
                "#           Context ID:",
                "#                63 6f 6f 6b 69 " +
                     "65                                 cookie")
         });


    // An invalid virtual list view response control.
    resultList.add(
         new Object[]
         {
           new Control(VirtualListViewResponseControl.
                VIRTUAL_LIST_VIEW_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " + VirtualListViewResponseControl.
                     VIRTUAL_LIST_VIEW_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid account usable response control that indicates the account is
    // usable.
    resultList.add(
         new Object[]
         {
           new AccountUsableResponseControl(12345),
           Arrays.asList(
                "#      Account Usable Response Control:",
                "#           OID:  " +
                     AccountUsableResponseControl.ACCOUNT_USABLE_RESPONSE_OID,
                "#           Account Is Usable:  true",
                "#           Password Is Expired:  false",
                "#           Must Change Password:  false",
                "#           Account Is Inactive:  false",
                "#           Seconds Until Password Expiration:  12345")
         });


    // A valid account usable response control that indicates the account is not
    // usable.
    resultList.add(
         new Object[]
         {
           new AccountUsableResponseControl(true, true, true, 12345, 67890),
           Arrays.asList(
                "#      Account Usable Response Control:",
                "#           OID:  " +
                     AccountUsableResponseControl.ACCOUNT_USABLE_RESPONSE_OID,
                "#           Account Is Usable:  false",
                "#           Unusable Reasons:",
                "#                The account has been locked or deactivated.",
                "#                The password must be changed before any " +
                     "other operations will be allowed.",
                "#                The password is expired.",
                "#                12345 grace logins are available.",
                "#                The account will be automatically unlocked " +
                     "in 67890 seconds.",
                "#           Password Is Expired:  true",
                "#           Must Change Password:  true",
                "#           Account Is Inactive:  true",
                "#           Remaining Grace Logins:  12345",
                "#           Seconds Until Account Unlock:  67890")
         });


    // An invalid account usable response control.
    resultList.add(
         new Object[]
         {
           new Control(
                AccountUsableResponseControl.ACCOUNT_USABLE_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " +
                     AccountUsableResponseControl.ACCOUNT_USABLE_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid assured replication response control that indicates the account
    // is usable.
    resultList.add(
         new Object[]
         {
           new AssuredReplicationResponseControl(
                AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS, true,
                "local message",
                AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION,
                false, "remote message", "csn",
                Arrays.asList(
                     new AssuredReplicationServerResult(
                          AssuredReplicationServerResultCode.COMPLETE,
                          (short) 12345, (short) 12346),
                     new AssuredReplicationServerResult(
                          AssuredReplicationServerResultCode.TIMEOUT,
                          (short) 12347, (short) 12348))),
           Arrays.asList(
                "#      Assured Replication Response Control:",
                "#           OID:  " + AssuredReplicationResponseControl.
                     ASSURED_REPLICATION_RESPONSE_OID,
                "#           Change Sequence Number:  csn",
                "#           Local Assurance Level:  PROCESSED_ALL_SERVERS",
                "#           Local Assurance Satisfied:  true",
                "#           Local Assurance Message:  local message",
                "#           Remote Assurance Level:  " +
                     "RECEIVED_ANY_REMOTE_LOCATION",
                "#           Remote Assurance Satisfied:  false",
                "#           Remote Assurance Message:  remote message",
                "#           Server Result:",
                "#                Server Result Code:  COMPLETE",
                "#                Replication Server ID:  12345",
                "#                Replica ID:  12346",
                "#           Server Result:",
                "#                Server Result Code:  TIMEOUT",
                "#                Replication Server ID:  12347",
                "#                Replica ID:  12348")
         });


    // An invalid assured replication response control.
    resultList.add(
         new Object[]
         {
           new Control(AssuredReplicationResponseControl.
                ASSURED_REPLICATION_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " + AssuredReplicationResponseControl.
                     ASSURED_REPLICATION_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid generate password response control without a password expiration
    // time.
    resultList.add(
         new Object[]
         {
           new GeneratePasswordResponseControl("generated-password", false,
                (Long) null),
           Arrays.asList(
                "#      Generate Password Response Control:",
                "#           OID:  " + GeneratePasswordResponseControl.
                     GENERATE_PASSWORD_RESPONSE_OID,
                "#           Generated Password:  generated-password",
                "#           Must Change Password:  false")
         });


    // A valid generate password response control with a password expiration
    // time.
    resultList.add(
         new Object[]
         {
           new GeneratePasswordResponseControl("generated-password", true,
                86400L),
           Arrays.asList(
                "#      Generate Password Response Control:",
                "#           OID:  " + GeneratePasswordResponseControl.
                     GENERATE_PASSWORD_RESPONSE_OID,
                "#           Generated Password:  generated-password",
                "#           Must Change Password:  true",
                "#           Seconds Until Expiration:  86400")
         });


    // An invalid generate password response control.
    resultList.add(
         new Object[]
         {
           new Control(GeneratePasswordResponseControl.
                GENERATE_PASSWORD_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " + GeneratePasswordResponseControl.
                     GENERATE_PASSWORD_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid get authorization entry response control for an unauthenticated
    // connection.
    resultList.add(
         new Object[]
         {
           new GetAuthorizationEntryResponseControl(false, true, "dn:", null,
                null, null),
           Arrays.asList(
                "#      Get Authorization Entry Response Control:",
                "#           OID:  " + GetAuthorizationEntryResponseControl.
                     GET_AUTHORIZATION_ENTRY_RESPONSE_OID,
                "#           Is Authenticated:  false")
         });


    // A valid get authorization entry response control for an authenticated
    // connection in which the authentication and authorization identities
    // match.
    resultList.add(
         new Object[]
         {
           new GetAuthorizationEntryResponseControl(true, true, "u:test.user",
                new ReadOnlyEntry(
                     "dn: uid=test.user,ou=People,dc=example,dc=com",
                     "objectClass: top",
                     "objectClass: person",
                     "objectClass: organizationalPerson",
                     "objectClass: inetOrgPerson",
                     "uid: test.user",
                     "givenName: Test",
                     "sn: User",
                     "cn: Test User"),
                null, null),
           Arrays.asList(
                "#      Get Authorization Entry Response Control:",
                "#           OID:  " + GetAuthorizationEntryResponseControl.
                     GET_AUTHORIZATION_ENTRY_RESPONSE_OID,
                "#           Is Authenticated:  true",
                "#           Authentication and Authorization Identities " +
                     "Match:  true",
                "#           Authentication Identity ID:  u:test.user",
                "#           Authentication Identity Entry:",
                "#                dn: uid=test.user,ou=People,dc=example," +
                     "dc=com",
                "#                objectClass: top",
                "#                objectClass: person",
                "#                objectClass: organizationalPerson",
                "#                objectClass: inetOrgPerson",
                "#                uid: test.user",
                "#                givenName: Test",
                "#                sn: User",
                "#                cn: Test User")
         });


    // A valid get authorization entry response control for an authenticated
    // connection in which the authentication and authorization identities
    // differ.
    resultList.add(
         new Object[]
         {
           new GetAuthorizationEntryResponseControl(true, false, "u:test.user",
                new ReadOnlyEntry(
                     "dn: uid=test.user,ou=People,dc=example,dc=com",
                     "objectClass: top",
                     "objectClass: person",
                     "objectClass: organizationalPerson",
                     "objectClass: inetOrgPerson",
                     "uid: test.user",
                     "givenName: Test",
                     "sn: User",
                     "cn: Test User"),
                "u:another.user",
                new ReadOnlyEntry(
                     "dn: uid=another.user,ou=People,dc=example,dc=com",
                     "objectClass: top",
                     "objectClass: person",
                     "objectClass: organizationalPerson",
                     "objectClass: inetOrgPerson",
                     "uid: another.user",
                     "givenName: Another",
                     "sn: User",
                     "cn: Another User")),
           Arrays.asList(
                "#      Get Authorization Entry Response Control:",
                "#           OID:  " + GetAuthorizationEntryResponseControl.
                     GET_AUTHORIZATION_ENTRY_RESPONSE_OID,
                "#           Is Authenticated:  true",
                "#           Authentication and Authorization Identities " +
                     "Match:  false",
                "#           Authentication Identity ID:  u:test.user",
                "#           Authentication Identity Entry:",
                "#                dn: uid=test.user,ou=People,dc=example," +
                     "dc=com",
                "#                objectClass: top",
                "#                objectClass: person",
                "#                objectClass: organizationalPerson",
                "#                objectClass: inetOrgPerson",
                "#                uid: test.user",
                "#                givenName: Test",
                "#                sn: User",
                "#                cn: Test User",
                "#           Authorization Identity ID:  u:another.user",
                "#           Authorization Identity Entry:",
                "#                dn: uid=another.user,ou=People,dc=example," +
                     "dc=com",
                "#                objectClass: top",
                "#                objectClass: person",
                "#                objectClass: organizationalPerson",
                "#                objectClass: inetOrgPerson",
                "#                uid: another.user",
                "#                givenName: Another",
                "#                sn: User",
                "#                cn: Another User")
         });


    // An invalid get authorization identity response control.
    resultList.add(
         new Object[]
         {
           new Control(GetAuthorizationEntryResponseControl.
                GET_AUTHORIZATION_ENTRY_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " + GetAuthorizationEntryResponseControl.
                     GET_AUTHORIZATION_ENTRY_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid get backend set ID response control with a single backend set ID.
    resultList.add(
         new Object[]
         {
           new GetBackendSetIDResponseControl("rpID", "bsID"),
           Arrays.asList(
                "#      Get Backend Set ID Response Control:",
                "#           OID:  " + GetBackendSetIDResponseControl.
                     GET_BACKEND_SET_ID_RESPONSE_OID,
                "#           Entry-Balancing Request Processor ID:  rpID",
                "#           Backend Set ID:  bsID")
         });


    // A valid get backend set ID response control with multiple backend set
    // IDs.
    resultList.add(
         new Object[]
         {
           new GetBackendSetIDResponseControl("rpID",
                Arrays.asList("bs1", "bs2")),
           Arrays.asList(
                "#      Get Backend Set ID Response Control:",
                "#           OID:  " + GetBackendSetIDResponseControl.
                     GET_BACKEND_SET_ID_RESPONSE_OID,
                "#           Entry-Balancing Request Processor ID:  rpID",
                "#           Backend Set ID:  bs1",
                "#           Backend Set ID:  bs2")
         });


    // An invalid get backend set ID response control.
    resultList.add(
         new Object[]
         {
           new Control(GetBackendSetIDResponseControl.
                GET_BACKEND_SET_ID_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " + GetBackendSetIDResponseControl.
                     GET_BACKEND_SET_ID_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid get password policy state issues response control without any
    // issues.
    resultList.add(
         new Object[]
         {
           new GetPasswordPolicyStateIssuesResponseControl(null, null, null),
           Arrays.asList(
                "#      Get Password Policy State Issues Response Control:",
                "#           OID:  " +
                     GetPasswordPolicyStateIssuesResponseControl.
                          GET_PASSWORD_POLICY_STATE_ISSUES_RESPONSE_OID)
         });


    // A valid get password policy state issues response control with multiple
    // notices, warnings, and errors, and an authentication failure reason
    resultList.add(
         new Object[]
         {
           new GetPasswordPolicyStateIssuesResponseControl(
                Arrays.asList(
                     new PasswordPolicyStateAccountUsabilityNotice(
                          PasswordPolicyStateAccountUsabilityNotice.
                               NOTICE_TYPE_IN_MINIMUM_PASSWORD_AGE,
                          PasswordPolicyStateAccountUsabilityNotice.
                               NOTICE_NAME_IN_MINIMUM_PASSWORD_AGE,
                          "You can't change your password yet"),
                     new PasswordPolicyStateAccountUsabilityNotice(
                          PasswordPolicyStateAccountUsabilityNotice.
                               NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                          PasswordPolicyStateAccountUsabilityNotice.
                               NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                          "You have a valid retired password")),
                Arrays.asList(
                     new PasswordPolicyStateAccountUsabilityWarning(
                          PasswordPolicyStateAccountUsabilityWarning.
                               WARNING_TYPE_ACCOUNT_EXPIRING,
                          PasswordPolicyStateAccountUsabilityWarning.
                               WARNING_NAME_ACCOUNT_EXPIRING,
                          "Your account will expire soon"),
                     new PasswordPolicyStateAccountUsabilityWarning(
                          PasswordPolicyStateAccountUsabilityWarning.
                               WARNING_TYPE_PASSWORD_EXPIRING,
                          PasswordPolicyStateAccountUsabilityWarning.
                               WARNING_NAME_PASSWORD_EXPIRING,
                          "Your password will expire soon")),
                Arrays.asList(
                     new PasswordPolicyStateAccountUsabilityError(
                          PasswordPolicyStateAccountUsabilityError.
                               ERROR_TYPE_ACCOUNT_DISABLED,
                          PasswordPolicyStateAccountUsabilityError.
                               ERROR_NAME_ACCOUNT_DISABLED,
                          "Your account is disabled"),
                     new PasswordPolicyStateAccountUsabilityError(
                          PasswordPolicyStateAccountUsabilityError.
                               ERROR_TYPE_ACCOUNT_EXPIRED,
                          PasswordPolicyStateAccountUsabilityError.
                               ERROR_NAME_ACCOUNT_EXPIRED,
                          "Your account is expired")),
                new AuthenticationFailureReason(
                     AuthenticationFailureReason.
                          FAILURE_TYPE_ACCOUNT_NOT_USABLE,
                     AuthenticationFailureReason.
                          FAILURE_NAME_ACCOUNT_NOT_USABLE,
                     "Your account is not usable")),
           Arrays.asList(
                "#      Get Password Policy State Issues Response Control:",
                "#           OID:  " +
                     GetPasswordPolicyStateIssuesResponseControl.
                          GET_PASSWORD_POLICY_STATE_ISSUES_RESPONSE_OID,
                "#           Authentication Failure Reason:",
                "#                Failure Type:  account-not-usable",
                "#                Failure Message:  Your account is not usable",
                "#           Account Usability Error:",
                "#                Error Name:  account-disabled",
                "#                Error Message:  Your account is disabled",
                "#           Account Usability Error:",
                "#                Error Name:  account-expired",
                "#                Error Message:  Your account is expired",
                "#           Account Usability Warning:",
                "#                Warning Name:  account-expiring",
                "#                Warning Message:  Your account will expire " +
                     "soon",
                "#           Account Usability Warning:",
                "#                Warning Name:  password-expiring",
                "#                Warning Message:  Your password will " +
                     "expire soon",
                "#           Account Usability Notice:",
                "#                Notice Name:  in-minimum-password-age",
                "#                Notice Message:  You can't change your " +
                     "password yet",
                "#           Account Usability Notice:",
                "#                Notice Name:  outstanding-retired-password",
                "#                Notice Message:  You have a valid retired " +
                     "password")
         });


    // An invalid get password policy state issues response control.
    resultList.add(
         new Object[]
         {
           new Control(GetPasswordPolicyStateIssuesResponseControl.
                GET_PASSWORD_POLICY_STATE_ISSUES_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " +
                     GetPasswordPolicyStateIssuesResponseControl.
                          GET_PASSWORD_POLICY_STATE_ISSUES_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid get recent login history response control without any successful
    // or failed attempts.
    resultList.add(
         new Object[]
         {
           new GetRecentLoginHistoryResponseControl(new RecentLoginHistory(
                null, null)),
           Arrays.asList(
                "#      Get Recent Login History Response Control:",
                "#           OID:  " + GetRecentLoginHistoryResponseControl.
                     GET_RECENT_LOGIN_HISTORY_RESPONSE_OID,
                "#           No Successful Attempts",
                "#           No Failed Attempts")
         });


    // A valid get recent login history response control with both successful
    // and failed attempts.
    final long currentTime = System.currentTimeMillis();
    final TreeSet<RecentLoginHistoryAttempt> successes = new TreeSet<>();
    successes.add(new RecentLoginHistoryAttempt(true, currentTime, "simple",
         "1.2.3.4", null, 0L));

    final TreeSet<RecentLoginHistoryAttempt> failures = new TreeSet<>();
    failures.add(new RecentLoginHistoryAttempt(false, (currentTime - 5_000L),
         "simple", "1.2.3.4", "invalid-credentials", 1L));

    RecentLoginHistory recentLoginHistory =
         new RecentLoginHistory(successes, failures);

    resultList.add(
         new Object[]
         {
           new GetRecentLoginHistoryResponseControl(recentLoginHistory),
           Arrays.asList(
                "#      Get Recent Login History Response Control:",
                "#           OID:  " + GetRecentLoginHistoryResponseControl.
                     GET_RECENT_LOGIN_HISTORY_RESPONSE_OID,
                "#           Successful Attempt:",
                "#                Timestamp:  " +
                     StaticUtils.encodeRFC3339Time(currentTime),
                "#                Authentication Method:  simple",
                "#                Client IP Address:  1.2.3.4",
                "#                Additional Attempt Count:  0",
                "#           Failed Attempt:",
                "#                Timestamp:  " +
                     StaticUtils.encodeRFC3339Time(currentTime - 5_000L),
                "#                Authentication Method:  simple",
                "#                Client IP Address:  1.2.3.4",
                "#                Failure Reason:  invalid-credentials",
                "#                Additional Attempt Count:  1")
         });


    // An invalid recent login history response control.
    resultList.add(
         new Object[]
         {
           new Control(GetRecentLoginHistoryResponseControl.
                GET_RECENT_LOGIN_HISTORY_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " +
                     GetRecentLoginHistoryResponseControl.
                          GET_RECENT_LOGIN_HISTORY_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid get server ID response control.
    resultList.add(
         new Object[]
         {
           new GetServerIDResponseControl("serverID"),
           Arrays.asList(
                "#      Get Server ID Response Control:",
                "#           OID:  " +
                     GetServerIDResponseControl.GET_SERVER_ID_RESPONSE_OID,
                "#           Server ID:  serverID")
         });


    // An invalid get server ID response control.
    resultList.add(
         new Object[]
         {
           new Control(GetServerIDResponseControl.GET_SERVER_ID_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " +
                     GetServerIDResponseControl.GET_SERVER_ID_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid get user resource limits response control with a minimal set of
    // fields and unlimited values where possible.
    resultList.add(
         new Object[]
         {
           new GetUserResourceLimitsResponseControl(0L, 0L, 0L, 0L, null, null),
           Arrays.asList(
                "#      Get User Resource Limits Response Control:",
                "#           OID:  " + GetUserResourceLimitsResponseControl.
                     GET_USER_RESOURCE_LIMITS_RESPONSE_OID,
                "#           Size Limit:  Unlimited",
                "#           Time Limit:  Unlimited",
                "#           Idle Time Limit:  Unlimited",
                "#           Lookthrough Limit:  Unlimited")
         });


    // A valid get user resource limits response control with all fields and
    // definite limits.
    resultList.add(
         new Object[]
         {
           new GetUserResourceLimitsResponseControl(12345L, 67890L, 98765L,
                54321L, "uid=equivalent.user,ou=People,dc=example,dc=com",
                "CCP",
                Arrays.asList(
                     "cn=Group 1,ou=Groups,dc=example,dc=com",
                     "cn=Group 2,ou=Groups,dc=example,dc=com"),
                Arrays.asList("bypass-read-acl", "config-read"),
                Arrays.asList(
                     new Attribute("other-attr-1", "value1"),
                     new Attribute("other-attr-2", "value2"))),
           Arrays.asList(
                "#      Get User Resource Limits Response Control:",
                "#           OID:  " + GetUserResourceLimitsResponseControl.
                     GET_USER_RESOURCE_LIMITS_RESPONSE_OID,
                "#           Size Limit:  12345",
                "#           Time Limit:  67890 seconds",
                "#           Idle Time Limit:  98765 seconds",
                "#           Lookthrough Limit:  54321",
                "#           Equivalent Authorization User DN:  " +
                     "uid=equivalent.user,ou=People,dc=example,dc=com",
                "#           Client Connection Policy Name:  CCP",
                "#           Group DNs:",
                "#                cn=Group 1,ou=Groups,dc=example,dc=com",
                "#                cn=Group 2,ou=Groups,dc=example,dc=com",
                "#           Privileges:",
                "#                bypass-read-acl",
                "#                config-read",
                "#           Other Attributes:",
                "#                other-attr-1: value1",
                "#                other-attr-2: value2")
         });


    // An invalid get user resource limits response control.
    resultList.add(
         new Object[]
         {
           new Control(GetUserResourceLimitsResponseControl.
                GET_USER_RESOURCE_LIMITS_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " + GetUserResourceLimitsResponseControl.
                     GET_USER_RESOURCE_LIMITS_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid intermediate client response control.
    resultList.add(
         new Object[]
         {
           new IntermediateClientResponseControl(
                new IntermediateClientResponseValue(
                     new IntermediateClientResponseValue(null,
                          "upstream.server.address", false,
                          "upstreamServerName", "upstreamSessionID",
                          "upstreamResponseID"),
                     "intermediate.server.address", true,
                     "intermediateServerName", "intermediateSessionID",
                     "intermediateResponseID")),
           Arrays.asList(
                "#      Intermediate Client Response Control:",
                "#           OID:  " + IntermediateClientResponseControl.
                     INTERMEDIATE_CLIENT_RESPONSE_OID,
                "#           Upstream Server Address:  " +
                     "intermediate.server.address",
                "#           Upstream Server Secure:  true",
                "#           Server Name:  intermediateServerName",
                "#           Server Session ID:  intermediateSessionID",
                "#           Server Response ID:  intermediateResponseID",
                "#           Upstream Response:",
                "#                Upstream Server Address:  " +
                     "upstream.server.address",
                "#                Upstream Server Secure:  false",
                "#                Server Name:  upstreamServerName",
                "#                Server Session ID:  upstreamSessionID",
                "#                Server Response ID:  upstreamResponseID")
         });


    // An invalid intermediate client response control.
    resultList.add(
         new Object[]
         {
           new Control(IntermediateClientResponseControl.
                INTERMEDIATE_CLIENT_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " + IntermediateClientResponseControl.
                     INTERMEDIATE_CLIENT_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid join result control.
    resultList.add(
         new Object[]
         {
           new JoinResultControl(ResultCode.SUCCESS, "diag",
                "dc=example,dc=com",
                Arrays.asList(
                     "ldap://ds1.example.com:389/dc=example,dc=com",
                     "ldap://ds2.example.com:389/dc=example,dc=com"),
                Arrays.asList(
                     new JoinedEntry(
                          new ReadOnlyEntry(
                               "dn: ou=joined 1,dc=example,dc=com",
                               "objectClass: top",
                               "objectClass: organizationalUnit",
                               "ou: joined 1"),
                          Arrays.asList(
                               new JoinedEntry(
                                    new ReadOnlyEntry(
                                         "dn: ou=joined 1a,dc=example,dc=com",
                                         "objectClass: top",
                                         "objectClass: organizationalUnit",
                                         "ou: joined 1a"),
                                    null),
                               new JoinedEntry(
                                    new ReadOnlyEntry(
                                         "dn: ou=joined 1b,dc=example,dc=com",
                                         "objectClass: top",
                                         "objectClass: organizationalUnit",
                                         "ou: joined 1b"),
                                    null))),
                     new JoinedEntry(
                          new ReadOnlyEntry(
                               "dn: ou=joined 2,dc=example,dc=com",
                               "objectClass: top",
                               "objectClass: organizationalUnit",
                               "ou: joined 2"),
                          Arrays.asList(
                               new JoinedEntry(
                                    new ReadOnlyEntry(
                                         "dn: ou=joined 2a,dc=example,dc=com",
                                         "objectClass: top",
                                         "objectClass: organizationalUnit",
                                         "ou: joined 2a"),
                                    null),
                               new JoinedEntry(
                                    new ReadOnlyEntry(
                                         "dn: ou=joined 2b,dc=example,dc=com",
                                         "objectClass: top",
                                         "objectClass: organizationalUnit",
                                         "ou: joined 2b"),
                                    null))))),
           Arrays.asList(
                "#      Join Result Control:",
                "#           OID:  " + JoinResultControl.JOIN_RESULT_OID,
                "#           Join Result Code:  0 (success)",
                "#           Join Diagnostic Message:  diag",
                "#           Join Matched DN:  dc=example,dc=com",
                "#           Join Referral URL:  " +
                     "ldap://ds1.example.com:389/dc=example,dc=com",
                "#           Join Referral URL:  " +
                     "ldap://ds2.example.com:389/dc=example,dc=com",
                "#           Joined With Entry:",
                "#                dn: ou=joined 1,dc=example,dc=com",
                "#                objectClass: top",
                "#                objectClass: organizationalUnit",
                "#                ou: joined 1",
                "#                     Joined With Entry:",
                "#                          dn: ou=joined 1a,dc=example,dc=com",
                "#                          objectClass: top",
                "#                          objectClass: organizationalUnit",
                "#                          ou: joined 1a",
                "#                     Joined With Entry:",
                "#                          dn: ou=joined 1b,dc=example,dc=com",
                "#                          objectClass: top",
                "#                          objectClass: organizationalUnit",
                "#                          ou: joined 1b",
                "#           Joined With Entry:",
                "#                dn: ou=joined 2,dc=example,dc=com",
                "#                objectClass: top",
                "#                objectClass: organizationalUnit",
                "#                ou: joined 2",
                "#                     Joined With Entry:",
                "#                          dn: ou=joined 2a,dc=example,dc=com",
                "#                          objectClass: top",
                "#                          objectClass: organizationalUnit",
                "#                          ou: joined 2a",
                "#                     Joined With Entry:",
                "#                          dn: ou=joined 2b,dc=example,dc=com",
                "#                          objectClass: top",
                "#                          objectClass: organizationalUnit",
                "#                          ou: joined 2b")
         });


    // An invalid join result control.
    resultList.add(
         new Object[]
         {
           new Control(JoinResultControl.JOIN_RESULT_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " + JoinResultControl.JOIN_RESULT_OID,
                "#           Is Critical:  false")
         });


    // A valid matching entry count response control for an examined count.
    resultList.add(
         new Object[]
         {
           MatchingEntryCountResponseControl.createExactCountResponse(
                12345, true, true,
                Arrays.asList(
                     "debug message 1",
                     "debug message 2")),
           Arrays.asList(
                "#      Matching Entry Count Response Control:",
                "#           OID:  " + MatchingEntryCountResponseControl.
                     MATCHING_ENTRY_COUNT_RESPONSE_OID,
                "#           Count Type:  Examined",
                "#           Count Value:  12345",
                "#           Search Is Indexed:  true",
                "#           Debug Info:",
                "#                debug message 1",
                "#                debug message 2")
         });


    // A valid matching entry count response control for an unexamined count.
    resultList.add(
         new Object[]
         {
           MatchingEntryCountResponseControl.createExactCountResponse(
                67890, false, true,
                Arrays.asList(
                     "debug message 1",
                     "debug message 2")),
           Arrays.asList(
                "#      Matching Entry Count Response Control:",
                "#           OID:  " + MatchingEntryCountResponseControl.
                     MATCHING_ENTRY_COUNT_RESPONSE_OID,
                "#           Count Type:  Unexamined",
                "#           Count Value:  67890",
                "#           Search Is Indexed:  true",
                "#           Debug Info:",
                "#                debug message 1",
                "#                debug message 2")
         });


    // A valid matching entry count response control for an upper bound count.
    resultList.add(
         new Object[]
         {
           MatchingEntryCountResponseControl.createUpperBoundResponse(
                98765, false,
                Arrays.asList(
                     "debug message 1",
                     "debug message 2")),
           Arrays.asList(
                "#      Matching Entry Count Response Control:",
                "#           OID:  " + MatchingEntryCountResponseControl.
                     MATCHING_ENTRY_COUNT_RESPONSE_OID,
                "#           Count Type:  Upper Bound",
                "#           Count Value:  98765",
                "#           Search Is Indexed:  false",
                "#           Debug Info:",
                "#                debug message 1",
                "#                debug message 2")
         });


    // A valid matching entry count response control for an unknown count.
    resultList.add(
         new Object[]
         {
           MatchingEntryCountResponseControl.createUnknownCountResponse(
                Arrays.asList(
                     "debug message 1",
                     "debug message 2")),
           Arrays.asList(
                "#      Matching Entry Count Response Control:",
                "#           OID:  " + MatchingEntryCountResponseControl.
                     MATCHING_ENTRY_COUNT_RESPONSE_OID,
                "#           Count Type:  Unknown",
                "#           Search Is Indexed:  false",
                "#           Debug Info:",
                "#                debug message 1",
                "#                debug message 2")
         });


    // An invalid matching entry count response control.
    resultList.add(
         new Object[]
         {
           new Control(MatchingEntryCountResponseControl.
                MATCHING_ENTRY_COUNT_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " + MatchingEntryCountResponseControl.
                     MATCHING_ENTRY_COUNT_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid password policy response control for a password that is about to
    // expire.
    resultList.add(
         new Object[]
         {
           new PasswordPolicyResponseControl(
                PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION, 12345, null),
           Arrays.asList(
                "#      Password Policy Response Control:",
                "#           OID:  " + PasswordPolicyResponseControl.
                     PASSWORD_POLICY_RESPONSE_OID,
                "#           Error Type:  None",
                "#           Warning Type:  time before expiration",
                "#           Warning Value:  12345")
         });


    // A valid password policy response control for an account that is locked.
    resultList.add(
         new Object[]
         {
           new PasswordPolicyResponseControl(null, -1,
                PasswordPolicyErrorType.ACCOUNT_LOCKED),
           Arrays.asList(
                "#      Password Policy Response Control:",
                "#           OID:  " + PasswordPolicyResponseControl.
                     PASSWORD_POLICY_RESPONSE_OID,
                "#           Error Type:  account locked",
                "#           Warning Type:  None")
         });


    // An invalid password policy response control.
    resultList.add(
         new Object[]
         {
           new Control(
                PasswordPolicyResponseControl.PASSWORD_POLICY_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " +
                     PasswordPolicyResponseControl.PASSWORD_POLICY_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid password validation details response control for a validation
    // details response.
    final LinkedHashMap<String,String> r1Map =
         new LinkedHashMap<String,String>(2);
    r1Map.put("prop1a", "value1a");
    r1Map.put("prop1b", "value1b");
    final LinkedHashMap<String,String> r2Map =
         new LinkedHashMap<String,String>(2);
    r2Map.put("prop2a", "value2a");
    r2Map.put("prop2b", "value2b");
    resultList.add(
         new Object[]
         {
           new PasswordValidationDetailsResponseControl(
                PasswordValidationDetailsResponseType.VALIDATION_DETAILS,
                Arrays.asList(
                     new PasswordQualityRequirementValidationResult(
                          new PasswordQualityRequirement(
                               "Requirement 1", "first-requirement", r1Map),
                          true, "Requirement 1 was satisfied"),
                     new PasswordQualityRequirementValidationResult(
                          new PasswordQualityRequirement(
                               "Requirement 2", "second-requirement", r2Map),
                          false, "Requirement 2 was not satisfied")),
                false, true, 12345),
           Arrays.asList(
                "#      Password Validation Details Response Control:",
                "#           OID:  " + PasswordValidationDetailsResponseControl.
                     PASSWORD_VALIDATION_DETAILS_RESPONSE_OID,
                "#           Result Type:  Validation Result",
                "#                Password Quality Requirement Validation " +
                     "Result:",
                "#                     Password Quality Requirement " +
                     "Description:  Requirement 1",
                "#                     Client-Side Validation Type:  " +
                     "first-requirement",
                "#                     Client-Side Validation Property:  " +
                     "prop1a=value1a",
                "#                     Client-Side Validation Property:  " +
                     "prop1b=value1b",
                "#                     Requirement Satisfied:  true",
                "#                     Additional Validation Info:  " +
                     "Requirement 1 was satisfied",
                "#                Password Quality Requirement Validation " +
                     "Result:",
                "#                     Password Quality Requirement " +
                     "Description:  Requirement 2",
                "#                     Client-Side Validation Type:  " +
                     "second-requirement",
                "#                     Client-Side Validation Property:  " +
                     "prop2a=value2a",
                "#                     Client-Side Validation Property:  " +
                     "prop2b=value2b",
                "#                     Requirement Satisfied:  false",
                "#                     Additional Validation Info:  " +
                     "Requirement 2 was not satisfied",
                "#           Missing Current Password:  false",
                "#           Must Change Password:  true",
                "#           Seconds Until Expiration:  12345")
         });


    // A valid password validation details response control for a "no password
    // provided" response.
    resultList.add(
         new Object[]
         {
           new PasswordValidationDetailsResponseControl(
                PasswordValidationDetailsResponseType.NO_PASSWORD_PROVIDED,
                null, true, false, null),
           Arrays.asList(
                "#      Password Validation Details Response Control:",
                "#           OID:  " + PasswordValidationDetailsResponseControl.
                     PASSWORD_VALIDATION_DETAILS_RESPONSE_OID,
                "#           Result Type:  No Password Provided",
                "#           Missing Current Password:  true",
                "#           Must Change Password:  false")
         });


    // A valid password validation details response control for a "multiple
    // passwords provided" response.
    resultList.add(
         new Object[]
         {
           new PasswordValidationDetailsResponseControl(
                PasswordValidationDetailsResponseType.
                     MULTIPLE_PASSWORDS_PROVIDED,
                null, true, false, null),
           Arrays.asList(
                "#      Password Validation Details Response Control:",
                "#           OID:  " + PasswordValidationDetailsResponseControl.
                     PASSWORD_VALIDATION_DETAILS_RESPONSE_OID,
                "#           Result Type:  Multiple Passwords Provided",
                "#           Missing Current Password:  true",
                "#           Must Change Password:  false")
         });


    // A valid password validation details response control for a "no validation
    // attempted" response.
    resultList.add(
         new Object[]
         {
           new PasswordValidationDetailsResponseControl(
                PasswordValidationDetailsResponseType.NO_VALIDATION_ATTEMPTED,
                null, true, false, null),
           Arrays.asList(
                "#      Password Validation Details Response Control:",
                "#           OID:  " + PasswordValidationDetailsResponseControl.
                     PASSWORD_VALIDATION_DETAILS_RESPONSE_OID,
                "#           Result Type:  No Validation Attempted",
                "#           Missing Current Password:  true",
                "#           Must Change Password:  false")
         });


    // An invalid password validation details response control.
    resultList.add(
         new Object[]
         {
           new Control(PasswordValidationDetailsResponseControl.
                PASSWORD_VALIDATION_DETAILS_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " + PasswordValidationDetailsResponseControl.
                     PASSWORD_VALIDATION_DETAILS_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid soft delete response control.
    resultList.add(
         new Object[]
         {
           new SoftDeleteResponseControl(
                "ou=test+entryUUID=" + uuid.toString() + ",dc=example,dc=com"),
           Arrays.asList(
                "#      Soft Delete Response Control:",
                "#           OID:  " +
                     SoftDeleteResponseControl.SOFT_DELETE_RESPONSE_OID,
                "#           Soft-Deleted Entry DN:  ou=test+entryUUID=" +
                     uuid.toString() + ",dc=example,dc=com")
         });


    // An invalid soft delete response control.
    resultList.add(
         new Object[]
         {
           new Control(SoftDeleteResponseControl.SOFT_DELETE_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " +
                     SoftDeleteResponseControl.SOFT_DELETE_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid transaction settings response control.
    resultList.add(
         new Object[]
         {
           new TransactionSettingsResponseControl(12345, true),
           Arrays.asList(
                "#      Transaction Settings Response Control:",
                "#           OID:  " + TransactionSettingsResponseControl.
                     TRANSACTION_SETTINGS_RESPONSE_OID,
                "#           Number of Lock Conflicts:  12345",
                "#           Backend Lock Acquired:  true")
         });


    // An invalid transaction settings response control.
    resultList.add(
         new Object[]
         {
           new Control(TransactionSettingsResponseControl.
                TRANSACTION_SETTINGS_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " + TransactionSettingsResponseControl.
                     TRANSACTION_SETTINGS_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    // A valid uniqueness response control in which all of the tests passed.
    resultList.add(
         new Object[]
         {
           new UniquenessResponseControl("all-passed", true, true, null),
           Arrays.asList(
                "#      Uniqueness Response Control:",
                "#           OID:  " + UniquenessResponseControl.
                     UNIQUENESS_RESPONSE_OID,
                "#           Uniqueness ID:  all-passed",
                "#           Pre-Commit Validation Status:  Passed",
                "#           Post-Commit Validation Status:  Passed")
         });


    // A valid uniqueness response control in which the pre-commit attempt
    // failed.
    resultList.add(
         new Object[]
         {
           new UniquenessResponseControl("pre-commit-failed", false, null,
                "The pre-commit attempt failed"),
           Arrays.asList(
                "#      Uniqueness Response Control:",
                "#           OID:  " + UniquenessResponseControl.
                     UNIQUENESS_RESPONSE_OID,
                "#           Uniqueness ID:  pre-commit-failed",
                "#           Pre-Commit Validation Status:  Failed",
                "#           Post-Commit Validation Status:  Not Attempted",
                "#           Message:  The pre-commit attempt failed")
         });


    // A valid uniqueness response control in which the pre-commit attempt
    // passed but the post-commit attempt failed.
    resultList.add(
         new Object[]
         {
           new UniquenessResponseControl("post-commit-failed", true, false,
                "The post-commit attempt failed"),
           Arrays.asList(
                "#      Uniqueness Response Control:",
                "#           OID:  " + UniquenessResponseControl.
                     UNIQUENESS_RESPONSE_OID,
                "#           Uniqueness ID:  post-commit-failed",
                "#           Pre-Commit Validation Status:  Passed",
                "#           Post-Commit Validation Status:  Failed",
                "#           Message:  The post-commit attempt failed")
         });


    // A valid uniqueness response control in which no validation was attempted.
    resultList.add(
         new Object[]
         {
           new UniquenessResponseControl("not-attempted", null, null,
                "No validation was attempted"),
           Arrays.asList(
                "#      Uniqueness Response Control:",
                "#           OID:  " + UniquenessResponseControl.
                     UNIQUENESS_RESPONSE_OID,
                "#           Uniqueness ID:  not-attempted",
                "#           Pre-Commit Validation Status:  Not Attempted",
                "#           Post-Commit Validation Status:  Not Attempted",
                "#           Message:  No validation was attempted")
         });


    // An invalid uniqueness response control.
    resultList.add(
         new Object[]
         {
           new Control(UniquenessResponseControl.UNIQUENESS_RESPONSE_OID),
           Arrays.asList(
                "#      Response Control:",
                "#           OID:  " + UniquenessResponseControl.
                     UNIQUENESS_RESPONSE_OID,
                "#           Is Critical:  false")
         });


    return resultList.iterator();
  }



  /**
   * Tests the behavior with wrapping.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithWrapping()
         throws Exception
  {
    final Control[] responseControls =
    {
      new PostReadResponseControl(new ReadOnlyEntry(
           "dn: uid=test.user,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: test.user",
           "givenName: Test",
           "sn: User",
           "cn: Test User",
           "description: This is long enough that it'll be wrapped"))
    };

    final LDAPResult result = new LDAPResult(2, ResultCode.SUCCESS,
         "This is a long diagnostic message that should require wrapping", null,
         null, responseControls);

    final List<String> expected = Arrays.asList(
                "#      Result Code:  0 (success)",
                "#      Diagnostic Message:  This is a long",
                "#           diagnostic message that should",
                "#           require wrapping",
                "#      Post-Read Response Control:",
                "#           OID:  1.3.6.1.1.13.2",
                "#           Post-Read Entry:",
                "#                dn: uid=test.user,ou=People,",
                "#                 dc=example,dc=com",
                "#                objectClass: top",
                "#                objectClass: person",
                "#                objectClass: organizationalP",
                "#                 erson",
                "#                objectClass: inetOrgPerson",
                "#                uid: test.user",
                "#                givenName: Test",
                "#                sn: User",
                "#                cn: Test User",
                "#                description: This is long en",
                "#                 ough that it'll be wrapped");

    final ArrayList<String> lines = new ArrayList<String>(expected.size());
    ResultUtils.formatResult(lines, result, true, false, 5, 45);
    assertEquals(lines, expected,
         "Expected:" + StaticUtils.EOL + toMultiLine(expected) + "Got:" +
              StaticUtils.EOL + toMultiLine(lines));
  }



  /**
   * Retrieves a multi-line representation of the contents of the provided list.
   *
   * @param  l  The list to format.
   *
   * @return  A multi-line representation of the contents of the provided list.
   */
  private static String toMultiLine(final List<String> l)
  {
    final StringBuilder buffer = new StringBuilder();

    for (final String s : l)
    {
      buffer.append("     ");
      buffer.append(s);
      buffer.append(StaticUtils.EOL);
    }

    return buffer.toString();
  }
}
