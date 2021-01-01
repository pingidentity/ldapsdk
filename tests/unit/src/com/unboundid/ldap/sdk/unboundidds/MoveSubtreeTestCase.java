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
package com.unboundid.ldap.sdk.unboundidds;



import java.io.File;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.controls.SubtreeDeleteRequestControl;
import com.unboundid.ldap.sdk.extensions.NoticeOfDisconnectionExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.controls.
            OperationPurposeRequestControl;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            SetSubtreeAccessibilityExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.SubtreeAccessibilityState;



/**
 * This class provides a set of test cases for the MoveSubtree class.
 */
public final class MoveSubtreeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic coverage for portions of the class that do not require any
   * LDAP communication.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutCommunication()
         throws Exception
  {
    final MoveSubtree s = new MoveSubtree(null, null);

    assertNotNull(s.getToolName());

    assertNotNull(s.getToolDescription());

    assertNotNull(s.getToolVersion());

    assertNotNull(s.getConnectionOptions());

    assertNotNull(s.getExampleUsages());

    assertFalse(s.supportsInteractiveMode());
    assertFalse(s.defaultsToInteractiveMode());

    final ReadOnlyEntry e = new ReadOnlyEntry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    assertNotNull(s.doPreAddProcessing(e));
    assertEquals(s.doPreAddProcessing(e), e);

    s.doPostAddProcessing(e);

    final DN dn = new DN("dc=example,dc=com");
    s.doPreDeleteProcessing(dn);

    s.doPostDeleteProcessing(dn);

    s.runTool("--help");
  }



  /**
   * Tests the move subtree method call with a successful simple move.
   * <BR><BR>
   * Access to two UnboundID Directory Server instances are required for
   * complete testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testSuccessfulTransactionMoveWithMethod()
         throws Exception
  {
    if (! isSecondDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection sourceConn = getAdminConnection();
    final LDAPConnection targetConn = getSecondAdminConnection();

    if (! serversSupportInteractiveTransactions(sourceConn, targetConn))
    {
      sourceConn.close();
      targetConn.close();
      return;
    }

    try
    {
      sourceConn.add(getTestBaseDN(), getBaseEntryAttributes());
      targetConn.add(getTestBaseDN(), getBaseEntryAttributes());

      sourceConn.add(
           "dn: ou=branch," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: branch");

      MoveSubtreeResult result =
           MoveSubtree.moveEntryWithInteractiveTransaction(sourceConn,
                targetConn, "ou=branch," + getTestBaseDN(), null, null);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);
      assertNull(result.getErrorMessage());
      assertNull(result.getAdminActionRequired());
      assertTrue(result.sourceServerAltered());
      assertTrue(result.targetServerAltered());
      assertEquals(result.getEntriesReadFromSource(), 1);
      assertEquals(result.getEntriesAddedToTarget(), 1);
      assertEquals(result.getEntriesDeletedFromSource(), 1);

      assertEntryMissing(sourceConn, "ou=branch," + getTestBaseDN());

      assertEntryExists(targetConn, "ou=branch," + getTestBaseDN());


      final OperationPurposeRequestControl opPurpose =
           new OperationPurposeRequestControl("move-subtree-test", "1.0",
                10, "testSuccessfulMove");
      final TestMoveSubtreeListener listener = new TestMoveSubtreeListener();

      result = MoveSubtree.moveEntryWithInteractiveTransaction(targetConn,
           sourceConn, "ou=branch," + getTestBaseDN(), opPurpose, listener);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);
      assertNull(result.getErrorMessage());
      assertNull(result.getAdminActionRequired());
      assertTrue(result.sourceServerAltered());
      assertTrue(result.targetServerAltered());
      assertEquals(result.getEntriesReadFromSource(), 1);
      assertEquals(result.getEntriesAddedToTarget(), 1);
      assertEquals(result.getEntriesDeletedFromSource(), 1);

      assertTrue(listener.preAddCalled());
      assertTrue(listener.postAddCalled());
      assertTrue(listener.preDeleteCalled());
      assertTrue(listener.postDeleteCalled());

      assertEntryExists(sourceConn, "ou=branch," + getTestBaseDN());

      assertEntryMissing(targetConn, "ou=branch," + getTestBaseDN());

      new MoveSubtree(null, null).handleUnsolicitedNotification(sourceConn,
           new NoticeOfDisconnectionExtendedResult(1, ResultCode.OTHER, "test",
                null, null, null));
    }
    finally
    {
      subtreeDelete(sourceConn);
      sourceConn.close();

      subtreeDelete(targetConn);
      targetConn.close();
    }
  }



  /**
   * Tests the move subtree tool with a successful simple move.
   * <BR><BR>
   * Access to two UnboundID Directory Server instances are required for
   * complete testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulTransactionMoveWithTool()
         throws Exception
  {
    if (! isSecondDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection sourceConn = getAdminConnection();
    final LDAPConnection targetConn = getSecondAdminConnection();

    try
    {
      sourceConn.add(getTestBaseDN(), getBaseEntryAttributes());
      targetConn.add(getTestBaseDN(), getBaseEntryAttributes());

      sourceConn.add(
           "dn: ou=branch," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: branch");


      final String[] args =
      {
        "--sourceHostname", getTestHost(),
        "--sourcePort", String.valueOf(getTestPort()),
        "--sourceBindDN", getTestBindDN(),
        "--sourceBindPassword", getTestBindPassword(),
        "--targetHostname", getSecondTestHost(),
        "--targetPort", String.valueOf(getSecondTestPort()),
        "--targetSASLOption", "mech=PLAIN",
        "--targetSASLOption", "authID=dn:" + getTestBindDN(),
        "--targetBindPassword", getTestBindPassword(),
        "--baseDN", "ou=branch," + getTestBaseDN(),
        "--sizeLimit", "1"
      };

      final ResultCode resultCode = MoveSubtree.main(args, null, null);
      assertEquals(resultCode, ResultCode.SUCCESS);

      assertEntryMissing(sourceConn, "ou=branch," + getTestBaseDN());

      assertEntryExists(targetConn, "ou=branch," + getTestBaseDN());
    }
    finally
    {
      subtreeDelete(sourceConn);
      sourceConn.close();

      subtreeDelete(targetConn);
      targetConn.close();
    }
  }



  /**
   * Tests the move subtree tool with a successful move of multiple subtrees
   * in which the tool is pointed at a file with the base DNs to move.
   * <BR><BR>
   * Access to two UnboundID Directory Server instances are required for
   * complete testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleTransactionMoveWithToolUsingFile()
         throws Exception
  {
    if (! isSecondDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection sourceConn = getAdminConnection();
    final LDAPConnection targetConn = getSecondAdminConnection();

    try
    {
      sourceConn.add(getTestBaseDN(), getBaseEntryAttributes());
      targetConn.add(getTestBaseDN(), getBaseEntryAttributes());

      sourceConn.add(
           "dn: ou=branch," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: branch");
      sourceConn.add(
           "dn: ou=branch2," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: branch");

      final File baseDNFile = createTempFile(
           "ou=branch," + getTestBaseDN(),
           "ou=branch2," + getTestBaseDN());

      final String[] args =
      {
        "--sourceHostname", getTestHost(),
        "--sourcePort", String.valueOf(getTestPort()),
        "--sourceBindDN", getTestBindDN(),
        "--sourceBindPassword", getTestBindPassword(),
        "--targetHostname", getSecondTestHost(),
        "--targetPort", String.valueOf(getSecondTestPort()),
        "--targetBindDN", getTestBindDN(),
        "--targetBindPassword", getTestBindPassword(),
        "--baseDNFile", baseDNFile.getAbsolutePath(),
        "--purpose", "testMultipleMoveWithToolUsingFile",
        "--sizeLimit", "1",
        "--verbose"
      };

      final ResultCode resultCode = MoveSubtree.main(args, null, null);
      assertEquals(resultCode, ResultCode.SUCCESS);

      assertEntryMissing(sourceConn, "ou=branch," + getTestBaseDN());
      assertEntryMissing(sourceConn, "ou=branch2," + getTestBaseDN());

      assertEntryExists(targetConn, "ou=branch," + getTestBaseDN());
      assertEntryExists(targetConn, "ou=branch2," + getTestBaseDN());
    }
    finally
    {
      subtreeDelete(sourceConn);
      sourceConn.close();

      subtreeDelete(targetConn);
      targetConn.close();
    }
  }



  /**
   * Tests the move subtree method call with a move that fails because the
   * source connection is not authenticated.
   * <BR><BR>
   * Access to two UnboundID Directory Server instances are required for
   * complete testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testFailedTransactionMoveSourceUnauthenticated()
         throws Exception
  {
    if (! isSecondDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection sourceConn = getAdminConnection();
    final LDAPConnection targetConn = getSecondAdminConnection();

    if (! serversSupportInteractiveTransactions(sourceConn, targetConn))
    {
      sourceConn.close();
      targetConn.close();
      return;
    }

    try
    {
      sourceConn.add(getTestBaseDN(), getBaseEntryAttributes());
      targetConn.add(getTestBaseDN(), getBaseEntryAttributes());

      sourceConn.add(
           "dn: ou=branch," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: branch");

      final LDAPConnection anonymousSourceConn = getUnauthenticatedConnection();

      final MoveSubtreeResult result =
           MoveSubtree.moveEntryWithInteractiveTransaction(
                anonymousSourceConn, targetConn, "ou=branch," + getTestBaseDN(),
                null, null);
      assertFalse(result.getResultCode() == ResultCode.SUCCESS);
      assertNotNull(result.getErrorMessage());
      assertFalse(result.sourceServerAltered());
      assertFalse(result.targetServerAltered());

      anonymousSourceConn.close();
    }
    finally
    {
      subtreeDelete(sourceConn);
      sourceConn.close();

      subtreeDelete(targetConn);
      targetConn.close();
    }
  }



  /**
   * Tests the move subtree method call with a move that fails because the
   * target connection is not authenticated.
   * <BR><BR>
   * Access to two UnboundID Directory Server instances are required for
   * complete testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testFailedTransactionMoveTargetUnauthenticated()
         throws Exception
  {
    if (! isSecondDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection sourceConn = getAdminConnection();
    final LDAPConnection targetConn = getSecondAdminConnection();

    if (! serversSupportInteractiveTransactions(sourceConn, targetConn))
    {
      sourceConn.close();
      targetConn.close();
      return;
    }

    try
    {
      sourceConn.add(getTestBaseDN(), getBaseEntryAttributes());
      targetConn.add(getTestBaseDN(), getBaseEntryAttributes());

      sourceConn.add(
           "dn: ou=branch," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: branch");

      final LDAPConnection anonymousTargetConn =
           getSecondUnauthenticatedConnection();

      final MoveSubtreeResult result =
           MoveSubtree.moveEntryWithInteractiveTransaction(sourceConn,
                anonymousTargetConn, "ou=branch," + getTestBaseDN(), null,
                null);
      assertFalse(result.getResultCode() == ResultCode.SUCCESS);
      assertNotNull(result.getErrorMessage());
      assertFalse(result.sourceServerAltered());
      assertFalse(result.targetServerAltered());

      anonymousTargetConn.close();
    }
    finally
    {
      subtreeDelete(sourceConn);
      sourceConn.close();

      subtreeDelete(targetConn);
      targetConn.close();
    }
  }



  /**
   * Tests the move subtree method call with a move that fails because the
   * specified subtree does not exist.
   * <BR><BR>
   * Access to two UnboundID Directory Server instances are required for
   * complete testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testFailedTransactionMoveBaseDNMissing()
         throws Exception
  {
    if (! isSecondDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection sourceConn = getAdminConnection();
    final LDAPConnection targetConn = getSecondAdminConnection();

    if (! serversSupportInteractiveTransactions(sourceConn, targetConn))
    {
      sourceConn.close();
      targetConn.close();
      return;
    }

    try
    {
      sourceConn.add(getTestBaseDN(), getBaseEntryAttributes());
      targetConn.add(getTestBaseDN(), getBaseEntryAttributes());

      final OperationPurposeRequestControl opPurpose =
           new OperationPurposeRequestControl("move-subtree-test", "1.0",
                10, "testSuccessfulMove");
      final MoveSubtreeResult result =
           MoveSubtree.moveEntryWithInteractiveTransaction(sourceConn,
                targetConn, "ou=missing," + getTestBaseDN(), opPurpose,
                null);
      assertFalse(result.getResultCode() == ResultCode.SUCCESS);
      assertNotNull(result.getErrorMessage());
      assertFalse(result.sourceServerAltered());
      assertFalse(result.targetServerAltered());
    }
    finally
    {
      subtreeDelete(sourceConn);
      sourceConn.close();

      subtreeDelete(targetConn);
      targetConn.close();
    }
  }



  /**
   * Tests the move subtree method call with a move that fails because the
   * base entry already exists in the target server.
   * <BR><BR>
   * Access to two UnboundID Directory Server instances are required for
   * complete testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testFailedTransactionMoveTargetBaseExists()
         throws Exception
  {
    if (! isSecondDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection sourceConn = getAdminConnection();
    final LDAPConnection targetConn = getSecondAdminConnection();

    if (! serversSupportInteractiveTransactions(sourceConn, targetConn))
    {
      sourceConn.close();
      targetConn.close();
      return;
    }

    try
    {
      sourceConn.add(getTestBaseDN(), getBaseEntryAttributes());
      targetConn.add(getTestBaseDN(), getBaseEntryAttributes());

      sourceConn.add(
           "dn: ou=branch," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: branch");

      targetConn.add(
           "dn: ou=branch," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: branch");

      final MoveSubtreeResult result =
           MoveSubtree.moveEntryWithInteractiveTransaction(sourceConn,
                targetConn, "ou=branch," + getTestBaseDN(), null, null);
      assertFalse(result.getResultCode() == ResultCode.SUCCESS);
      assertNotNull(result.getErrorMessage());
      assertFalse(result.sourceServerAltered());
      assertFalse(result.targetServerAltered());
    }
    finally
    {
      subtreeDelete(sourceConn);
      sourceConn.close();

      subtreeDelete(targetConn);
      targetConn.close();
    }
  }



  /**
   * Tests the move subtree method call with a move that fails because the
   * size limit is exceeded.
   * <BR><BR>
   * Access to two UnboundID Directory Server instances are required for
   * complete testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testFailedTransactionMoveSizeLimitExceeded()
         throws Exception
  {
    if (! isSecondDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection sourceConn = getAdminConnection();
    final LDAPConnection targetConn = getSecondAdminConnection();

    if (! serversSupportInteractiveTransactions(sourceConn, targetConn))
    {
      sourceConn.close();
      targetConn.close();
      return;
    }

    try
    {
      sourceConn.add(getTestBaseDN(), getBaseEntryAttributes());
      targetConn.add(getTestBaseDN(), getBaseEntryAttributes());

      sourceConn.add(
           "dn: ou=branch," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: branch");

      for (int i=1; i <= 10; i++)
      {
        sourceConn.add(
             "dn: ou=sub" + i + ",ou=branch," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: sub" + i);
      }

      final MoveSubtreeResult result =
           MoveSubtree.moveEntryWithInteractiveTransaction(sourceConn,
                targetConn, "ou=branch," + getTestBaseDN(), null, null);
      assertFalse(result.getResultCode() == ResultCode.SUCCESS);
      assertNotNull(result.getErrorMessage());
      assertFalse(result.sourceServerAltered());
      assertFalse(result.targetServerAltered());
    }
    finally
    {
      subtreeDelete(sourceConn);
      sourceConn.close();

      subtreeDelete(targetConn);
      targetConn.close();
    }
  }



  /**
   * Tests the move subtree tool with an empty base DN file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMoveWithToolUsingEmptyFile()
         throws Exception
  {
    final File baseDNFile = createTempFile();

    final String[] args =
    {
      "--sourceHostname", "localhost",
      "--sourcePort", "1234",
      "--sourceBindDN", getTestBindDN(),
      "--sourceBindPassword", getTestBindPassword(),
      "--targetHostname", "localhost",
      "--targetPort", "5678",
      "--targetBindDN", getTestBindDN(),
      "--targetBindPassword", getTestBindPassword(),
      "--baseDNFile", baseDNFile.getAbsolutePath(),
      "--purpose", "testMultipleMoveWithToolUsingFile",
      "--verbose"
    };

    final ResultCode resultCode = MoveSubtree.main(args, null, null);
    assertFalse(resultCode == ResultCode.SUCCESS);
  }



  /**
   * Tests the move subtree tool with a base DN that doesn't exist.
   * <BR><BR>
   * Access to two UnboundID Directory Server instances are required for
   * complete testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransactionMoveWithToolNoSuchEntry()
         throws Exception
  {
    if (! isSecondDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection sourceConn = getAdminConnection();
    final LDAPConnection targetConn = getSecondAdminConnection();

    try
    {
      sourceConn.add(getTestBaseDN(), getBaseEntryAttributes());
      targetConn.add(getTestBaseDN(), getBaseEntryAttributes());


      final String[] args =
      {
        "--sourceHostname", getTestHost(),
        "--sourcePort", String.valueOf(getTestPort()),
        "--sourceBindDN", getTestBindDN(),
        "--sourceBindPassword", getTestBindPassword(),
        "--targetHostname", getSecondTestHost(),
        "--targetPort", String.valueOf(getSecondTestPort()),
        "--targetBindDN", getTestBindDN(),
        "--targetBindPassword", getTestBindPassword(),
        "--baseDN", "ou=branch," + getTestBaseDN()
      };

      final ResultCode resultCode = MoveSubtree.main(args, null, null);
      assertFalse(resultCode == ResultCode.SUCCESS);
    }
    finally
    {
      subtreeDelete(sourceConn);
      sourceConn.close();

      subtreeDelete(targetConn);
      targetConn.close();
    }
  }



  /**
   * Tests the move subtree method call with a successful simple move.
   * <BR><BR>
   * Access to two UnboundID Directory Server instances are required for
   * complete testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulAccessibilityMoveWithMethod()
         throws Exception
  {
    if (! isSecondDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection sourceConn = getAdminConnection();
    final LDAPConnection targetConn = getSecondAdminConnection();

    try
    {
      sourceConn.add(getTestBaseDN(), getBaseEntryAttributes());
      targetConn.add(getTestBaseDN(), getBaseEntryAttributes());

      sourceConn.add(
           "dn: ou=branch," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: branch");

      for (int i=1; i <= 10; i++)
      {
        sourceConn.add(
             "dn: ou=sub" + i + ",ou=branch," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: sub" + i);
      }

      MoveSubtreeResult result =
           MoveSubtree.moveSubtreeWithRestrictedAccessibility(sourceConn,
                targetConn, "ou=branch," + getTestBaseDN(), 50, null, null);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);
      assertNull(result.getErrorMessage());
      assertNull(result.getAdminActionRequired());
      assertTrue(result.sourceServerAltered());
      assertTrue(result.targetServerAltered());
      assertEquals(result.getEntriesReadFromSource(), 11);
      assertEquals(result.getEntriesAddedToTarget(), 11);
      assertEquals(result.getEntriesDeletedFromSource(), 11);

      assertEntryMissing(sourceConn, "ou=branch," + getTestBaseDN());

      assertEntryExists(targetConn, "ou=branch," + getTestBaseDN());
      assertEntryExists(targetConn, "ou=sub1,ou=branch," + getTestBaseDN());


      final OperationPurposeRequestControl opPurpose =
           new OperationPurposeRequestControl("move-subtree-test", "1.0",
                10, "testSuccessfulMove");
      final TestMoveSubtreeListener listener = new TestMoveSubtreeListener();

      result = MoveSubtree.moveSubtreeWithRestrictedAccessibility(targetConn,
           sourceConn, "ou=branch," + getTestBaseDN(), 50, opPurpose, listener);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);
      assertNull(result.getErrorMessage());
      assertNull(result.getAdminActionRequired());
      assertTrue(result.sourceServerAltered());
      assertTrue(result.targetServerAltered());
      assertEquals(result.getEntriesReadFromSource(), 11);
      assertEquals(result.getEntriesAddedToTarget(), 11);
      assertEquals(result.getEntriesDeletedFromSource(), 11);

      assertTrue(listener.preAddCalled());
      assertTrue(listener.postAddCalled());
      assertTrue(listener.preDeleteCalled());
      assertTrue(listener.postDeleteCalled());

      assertEntryExists(sourceConn, "ou=branch," + getTestBaseDN());
      assertEntryExists(sourceConn, "ou=sub1,ou=branch," + getTestBaseDN());

      assertEntryMissing(targetConn, "ou=branch," + getTestBaseDN());

      new MoveSubtree(null, null).handleUnsolicitedNotification(sourceConn,
           new NoticeOfDisconnectionExtendedResult(1, ResultCode.OTHER, "test",
                null, null, null));
    }
    finally
    {
      subtreeDelete(sourceConn);
      sourceConn.close();

      subtreeDelete(targetConn);
      targetConn.close();
    }
  }



  /**
   * Tests the move subtree tool with a successful simple move.
   * <BR><BR>
   * Access to two UnboundID Directory Server instances are required for
   * complete testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulAccessibilityMoveWithTool()
         throws Exception
  {
    if (! isSecondDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection sourceConn = getAdminConnection();
    final LDAPConnection targetConn = getSecondAdminConnection();

    try
    {
      sourceConn.add(getTestBaseDN(), getBaseEntryAttributes());
      targetConn.add(getTestBaseDN(), getBaseEntryAttributes());

      sourceConn.add(
           "dn: ou=branch," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: branch");

      for (int i=1; i <= 10; i++)
      {
        sourceConn.add(
             "dn: ou=sub" + i + ",ou=branch," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: sub" + i);
      }


      final String[] args =
      {
        "--sourceHostname", getTestHost(),
        "--sourcePort", String.valueOf(getTestPort()),
        "--sourceBindDN", getTestBindDN(),
        "--sourceBindPassword", getTestBindPassword(),
        "--targetHostname", getSecondTestHost(),
        "--targetPort", String.valueOf(getSecondTestPort()),
        "--targetSASLOption", "mech=PLAIN",
        "--targetSASLOption", "authID=dn:" + getTestBindDN(),
        "--targetBindPassword", getTestBindPassword(),
        "--baseDN", "ou=branch," + getTestBaseDN()
      };

      final ResultCode resultCode = MoveSubtree.main(args, null, null);
      assertEquals(resultCode, ResultCode.SUCCESS);

      assertEntryMissing(sourceConn, "ou=branch," + getTestBaseDN());

      assertEntryExists(targetConn, "ou=branch," + getTestBaseDN());
      assertEntryExists(targetConn, "ou=sub1,ou=branch," + getTestBaseDN());
    }
    finally
    {
      subtreeDelete(sourceConn);
      sourceConn.close();

      subtreeDelete(targetConn);
      targetConn.close();
    }
  }



  /**
   * Tests the move subtree method call with a move that fails because the
   * specified subtree does not exist.
   * <BR><BR>
   * Access to two UnboundID Directory Server instances are required for
   * complete testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailedAccessibilityMoveBaseDNMissing()
         throws Exception
  {
    if (! isSecondDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection sourceConn = getAdminConnection();
    final LDAPConnection targetConn = getSecondAdminConnection();

    try
    {
      sourceConn.add(getTestBaseDN(), getBaseEntryAttributes());
      targetConn.add(getTestBaseDN(), getBaseEntryAttributes());

      final OperationPurposeRequestControl opPurpose =
           new OperationPurposeRequestControl("move-subtree-test", "1.0",
                10, "testSuccessfulMove");
      final MoveSubtreeResult result =
           MoveSubtree.moveSubtreeWithRestrictedAccessibility(sourceConn,
                targetConn, "ou=missing," + getTestBaseDN(), 5, opPurpose,
                null);
      assertFalse(result.getResultCode() == ResultCode.SUCCESS);
      assertNotNull(result.getErrorMessage());
      assertFalse(result.sourceServerAltered());
      assertFalse(result.targetServerAltered());
    }
    finally
    {
      subtreeDelete(sourceConn);
      sourceConn.close();

      subtreeDelete(targetConn);
      targetConn.close();
    }
  }



  /**
   * Tests the move subtree method call with a move that fails because the
   * base entry already exists in the target server.
   * <BR><BR>
   * Access to two UnboundID Directory Server instances are required for
   * complete testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailedAccessibilityMoveTargetBaseExists()
         throws Exception
  {
    if (! isSecondDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection sourceConn = getAdminConnection();
    final LDAPConnection targetConn = getSecondAdminConnection();

    try
    {
      sourceConn.add(getTestBaseDN(), getBaseEntryAttributes());
      targetConn.add(getTestBaseDN(), getBaseEntryAttributes());

      sourceConn.add(
           "dn: ou=branch," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: branch");

      targetConn.add(
           "dn: ou=branch," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: branch");

      for (int i=1; i <= 10; i++)
      {
        sourceConn.add(
             "dn: ou=sub" + i + ",ou=branch," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: sub" + i);
      }

      final MoveSubtreeResult result =
           MoveSubtree.moveSubtreeWithRestrictedAccessibility(sourceConn,
                targetConn, "ou=branch," + getTestBaseDN(), 100, null, null);
      assertFalse(result.getResultCode() == ResultCode.SUCCESS);
      assertNotNull(result.getErrorMessage());
      assertFalse(result.sourceServerAltered());
      assertFalse(result.targetServerAltered());
    }
    finally
    {
      subtreeDelete(sourceConn);
      sourceConn.close();

      subtreeDelete(targetConn);
      targetConn.close();
    }
  }



  /**
   * Tests the move subtree method call with a move that fails because the
   * size limit is exceeded.
   * <BR><BR>
   * Access to two UnboundID Directory Server instances are required for
   * complete testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailedAccessibilityMoveSizeLimitExceeded()
         throws Exception
  {
    if (! isSecondDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection sourceConn = getAdminConnection();
    final LDAPConnection targetConn = getSecondAdminConnection();

    try
    {
      sourceConn.add(getTestBaseDN(), getBaseEntryAttributes());
      targetConn.add(getTestBaseDN(), getBaseEntryAttributes());

      sourceConn.add(
           "dn: ou=branch," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: branch");

      for (int i=1; i <= 10; i++)
      {
        sourceConn.add(
             "dn: ou=sub" + i + ",ou=branch," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: sub" + i);
      }

      final MoveSubtreeResult result =
           MoveSubtree.moveSubtreeWithRestrictedAccessibility(sourceConn,
                targetConn, "ou=branch," + getTestBaseDN(), 5, null, null);
      assertFalse(result.getResultCode() == ResultCode.SUCCESS);
      assertNotNull(result.getErrorMessage());
      assertFalse(result.sourceServerAltered());
      assertFalse(result.targetServerAltered());
    }
    finally
    {
      subtreeDelete(sourceConn);
      sourceConn.close();

      subtreeDelete(targetConn);
      targetConn.close();
    }
  }



  /**
   * Tests the move-subtree tool with the same host and port values specified
   * for both the source and target server.
   * <BR><BR>
   * Access to an UnboundID Directory Server instance is required for complete
   * testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToolWithSameSourceAndTarget()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] args =
    {
      "--sourceHostname", getTestHost(),
      "--sourcePort", String.valueOf(getTestPort()),
      "--sourceBindDN", getTestBindDN(),
      "--sourceBindPassword", getTestBindPassword(),
      "--targetHostname", getTestHost(),
      "--targetPort", String.valueOf(getTestPort()),
      "--targetSASLOption", "mech=PLAIN",
      "--targetSASLOption", "authID=dn:" + getTestBindDN(),
      "--targetBindPassword", getTestBindPassword(),
      "--baseDN", "ou=branch," + getTestBaseDN(),
      "--sizeLimit", "1"
    };

    final ResultCode resultCode = MoveSubtree.main(args, null, null);
    assertFalse(resultCode == ResultCode.SUCCESS);
  }



  /**
   * Tests the move-subtree tool with the different host-port combination for
   * the source and target but that actually reference the same server instance
   * (one connection in the clear and the other over SSL).
   * <BR><BR>
   * Access to an SSL-enabled UnboundID Directory Server instance is required
   * for complete testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToolWithSameSystemButDifferentPorts()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] args =
    {
      "--sourceHostname", getTestHost(),
      "--sourcePort", String.valueOf(getTestPort()),
      "--sourceBindDN", getTestBindDN(),
      "--sourceBindPassword", getTestBindPassword(),
      "--targetHostname", getTestHost(),
      "--targetPort", String.valueOf(getTestSSLPort()),
      "--targetUseSSL",
      "--targetTrustAll",
      "--targetSASLOption", "mech=PLAIN",
      "--targetSASLOption", "authID=dn:" + getTestBindDN(),
      "--targetBindPassword", getTestBindPassword(),
      "--baseDN", "ou=branch," + getTestBaseDN(),
      "--sizeLimit", "1"
    };

    final ResultCode resultCode = MoveSubtree.main(args, null, null);
    assertFalse(resultCode == ResultCode.SUCCESS);
  }



  /**
   * Performs a subtree delete to remove the test base entry and all of its
   * subordinates in the server to which the connection is established.
   *
   * @param  c  The connection in which to process the delete.
   */
  private static void subtreeDelete(final LDAPConnection c)
  {
    try
    {
      c.delete(new DeleteRequest(getTestBaseDN(),
           new Control[] { new SubtreeDeleteRequestControl(true) }));
    } catch (final Exception e) {}
  }



  /**
   * Tests the behavior of the checkInitialAccessibility method with a malformed
   * base DN.
   * <BR><BR>
   * Access to two UnboundID Directory Server instances are required for
   * complete testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCheckInitialAccessibilityMalformedBaseDN()
         throws Exception
  {
    if (! isSecondDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection sourceConn = getAdminConnection();
    final LDAPConnection targetConn = getSecondAdminConnection();

    try
    {
      sourceConn.add(getTestBaseDN(), getBaseEntryAttributes());
      targetConn.add(getTestBaseDN(), getBaseEntryAttributes());

      final MoveSubtreeResult result =
           MoveSubtree.moveSubtreeWithRestrictedAccessibility(sourceConn,
                targetConn, "malformed", 0, null, null);
      assertFalse(result.getResultCode() == ResultCode.SUCCESS);
    }
    finally
    {
      sourceConn.delete(getTestBaseDN());
      sourceConn.close();

      targetConn.delete(getTestBaseDN());
      targetConn.close();
    }
  }



  /**
   * Tests the behavior of the checkInitialAccessibility method with a state
   * that emulates the tool being interrupted during add processing.
   * <BR><BR>
   * Access to two UnboundID Directory Server instances are required for
   * complete testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCheckInitialAccessibilityInterruptedDuringAdd()
         throws Exception
  {
    if (! isSecondDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection sourceConn = getAdminConnection();
    final LDAPConnection targetConn = getSecondAdminConnection();

    try
    {
      sourceConn.add(getTestBaseDN(), getBaseEntryAttributes());
      targetConn.add(getTestBaseDN(), getBaseEntryAttributes());

      setState(sourceConn, "ou=People," + getTestBaseDN(),
           SubtreeAccessibilityState.READ_ONLY_BIND_ALLOWED);
      setState(targetConn, "ou=People," + getTestBaseDN(),
           SubtreeAccessibilityState.HIDDEN);

      final MoveSubtreeResult result =
           MoveSubtree.moveSubtreeWithRestrictedAccessibility(sourceConn,
                targetConn, "ou=People," + getTestBaseDN(), 0, null, null);
      assertFalse(result.getResultCode() == ResultCode.SUCCESS);
    }
    finally
    {
      setState(sourceConn, "ou=People," + getTestBaseDN(),
           SubtreeAccessibilityState.ACCESSIBLE);
      sourceConn.delete(getTestBaseDN());
      sourceConn.close();

      setState(targetConn, "ou=People," + getTestBaseDN(),
           SubtreeAccessibilityState.ACCESSIBLE);
      targetConn.delete(getTestBaseDN());
      targetConn.close();
    }
  }



  /**
   * Tests the behavior of the checkInitialAccessibility method with a state
   * that emulates the tool being interrupted during delete processing.
   * <BR><BR>
   * Access to two UnboundID Directory Server instances are required for
   * complete testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCheckInitialAccessibilityInterruptedDuringDelete()
         throws Exception
  {
    if (! isSecondDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection sourceConn = getAdminConnection();
    final LDAPConnection targetConn = getSecondAdminConnection();

    try
    {
      sourceConn.add(getTestBaseDN(), getBaseEntryAttributes());
      targetConn.add(getTestBaseDN(), getBaseEntryAttributes());

      setState(sourceConn, "ou=People," + getTestBaseDN(),
           SubtreeAccessibilityState.HIDDEN);

      final MoveSubtreeResult result =
           MoveSubtree.moveSubtreeWithRestrictedAccessibility(sourceConn,
                targetConn, "ou=People," + getTestBaseDN(), 0, null, null);
      assertFalse(result.getResultCode() == ResultCode.SUCCESS);
    }
    finally
    {
      setState(sourceConn, "ou=People," + getTestBaseDN(),
           SubtreeAccessibilityState.ACCESSIBLE);
      sourceConn.delete(getTestBaseDN());
      sourceConn.close();

      targetConn.delete(getTestBaseDN());
      targetConn.close();
    }
  }



  /**
   * Tests the behavior of the checkInitialAccessibility method with a state
   * that isn't normally used during move-subtree processing, but with a
   * base DN that exactly matches the subtree restrictions.
   * <BR><BR>
   * Access to two UnboundID Directory Server instances are required for
   * complete testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCheckInitialAccessibilityUnexpectedExactStateCombination()
         throws Exception
  {
    if (! isSecondDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection sourceConn = getAdminConnection();
    final LDAPConnection targetConn = getSecondAdminConnection();

    try
    {
      sourceConn.add(getTestBaseDN(), getBaseEntryAttributes());
      targetConn.add(getTestBaseDN(), getBaseEntryAttributes());

      setState(sourceConn, "ou=People," + getTestBaseDN(),
           SubtreeAccessibilityState.HIDDEN);
      setState(targetConn, "ou=People," + getTestBaseDN(),
           SubtreeAccessibilityState.HIDDEN);

      final MoveSubtreeResult result =
           MoveSubtree.moveSubtreeWithRestrictedAccessibility(sourceConn,
                targetConn, "ou=People," + getTestBaseDN(), 0, null, null);
      assertFalse(result.getResultCode() == ResultCode.SUCCESS);
    }
    finally
    {
      setState(sourceConn, "ou=People," + getTestBaseDN(),
           SubtreeAccessibilityState.ACCESSIBLE);
      sourceConn.delete(getTestBaseDN());
      sourceConn.close();

      setState(targetConn, "ou=People," + getTestBaseDN(),
           SubtreeAccessibilityState.ACCESSIBLE);
      targetConn.delete(getTestBaseDN());
      targetConn.close();
    }
  }



  /**
   * Applies the specified subtree accessibility state in Directory Server.
   *
   * @param  conn    The connection to use to communicate with the Directory
   *                 Server.
   * @param  baseDN  The base DN for which to set the accessibility state.
   * @param  state   The accessibility state to apply.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void setState(final LDAPConnection conn, final String baseDN,
                               final SubtreeAccessibilityState state)
          throws Exception
  {
    final SetSubtreeAccessibilityExtendedRequest request;
    switch(state)
    {
      case ACCESSIBLE:
        request = SetSubtreeAccessibilityExtendedRequest.
             createSetAccessibleRequest(baseDN);
        break;
      case HIDDEN:
        request = SetSubtreeAccessibilityExtendedRequest.
             createSetHiddenRequest(baseDN, getTestBindDN());
        break;
      case READ_ONLY_BIND_ALLOWED:
        request = SetSubtreeAccessibilityExtendedRequest.
             createSetReadOnlyRequest(baseDN, true, getTestBindDN());
        break;
      case READ_ONLY_BIND_DENIED:
        request = SetSubtreeAccessibilityExtendedRequest.
             createSetReadOnlyRequest(baseDN, false, getTestBindDN());
        break;
      default:
        throw new AssertionError("Unsupported accessibility state:  " +
             state.name());
    }

    final ExtendedResult result = conn.processExtendedOperation(request);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
  }



  /**
   * Determines whether both the source and target servers support interactive
   * transactions.
   *
   * @param  sourceConn  A connection that may be used to interact with the
   *                     source server.
   * @param  targetConn  A connection that may be used to interact with the
   *                     target server.
   *
   * @return  {@code true} if both servers support interactive transactions, or
   *          {@code false} if at least one server does not support interactive
   *          transactions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @SuppressWarnings("deprecation")
  private static boolean serversSupportInteractiveTransactions(
                             final LDAPConnection sourceConn,
                             final LDAPConnection targetConn)
          throws Exception
  {
    final RootDSE sourceRootDSE = sourceConn.getRootDSE();
    assertNotNull(sourceRootDSE);

    if (! sourceRootDSE.supportsExtendedOperation(com.unboundid.ldap.sdk.
         unboundidds.extensions.StartInteractiveTransactionExtendedRequest.
              START_INTERACTIVE_TRANSACTION_REQUEST_OID))
    {
      return false;
    }

    final RootDSE targetRootDSE = targetConn.getRootDSE();
    assertNotNull(targetRootDSE);

    if (! targetRootDSE.supportsExtendedOperation(com.unboundid.ldap.sdk.
         unboundidds.extensions.StartInteractiveTransactionExtendedRequest.
              START_INTERACTIVE_TRANSACTION_REQUEST_OID))
    {
      return false;
    }

    return true;
  }
}
