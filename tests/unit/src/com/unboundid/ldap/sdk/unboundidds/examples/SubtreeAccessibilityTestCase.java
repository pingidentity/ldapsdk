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
package com.unboundid.ldap.sdk.unboundidds.examples;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            GetSubtreeAccessibilityExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            GetSubtreeAccessibilityExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            SetSubtreeAccessibilityExtendedRequest;



/**
 * This class provides a set of test cases for the subtree accessibility tool.
 */
public final class SubtreeAccessibilityTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasic()
         throws Exception
  {
    final SubtreeAccessibility tool = new SubtreeAccessibility(null, null);

    assertNotNull(tool.getToolName());

    assertNotNull(tool.getToolDescription());

    assertNotNull(tool.getToolVersion());

    assertNotNull(tool.getExampleUsages());

    assertTrue(tool.supportsInteractiveMode());
    assertTrue(tool.defaultsToInteractiveMode());
  }



  /**
   * Tests the ability to obtain usage information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsage()
         throws Exception
  {
    final String[] args =
    {
      "--help"
    };

    assertEquals(
         SubtreeAccessibility.main(args, null, null),
         ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior of the tool when actually interacting with a server.
   * <BR><BR>
   * Access to a Directory Server instance that supports the get and set subtree
   * accessibility operations is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testServerInteraction()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection conn = getAdminConnection();

    try
    {
      final RootDSE rootDSE = conn.getRootDSE();
      if (! (rootDSE.supportsExtendedOperation(
           GetSubtreeAccessibilityExtendedRequest.
                GET_SUBTREE_ACCESSIBILITY_REQUEST_OID) &&
           rootDSE.supportsExtendedOperation(
                SetSubtreeAccessibilityExtendedRequest.
                     SET_SUBTREE_ACCESSIBILITY_REQUEST_OID)))
      {
        return;
      }


      // Ensure that the base entry exists.
      conn.add(getTestBaseDN(), getBaseEntryAttributes());


      // Verify that the server doesn't have any restrictions defined.
      GetSubtreeAccessibilityExtendedResult getResult =
           (GetSubtreeAccessibilityExtendedResult)
           conn.processExtendedOperation(
                new GetSubtreeAccessibilityExtendedRequest());
      assertResultCodeEquals(getResult, ResultCode.SUCCESS);
      assertNotNull(getResult.getAccessibilityRestrictions());
      assertTrue(getResult.getAccessibilityRestrictions().isEmpty());


      // Verify that we can use the tool in "get" mode with no restrictions
      // defined.
      String[] args =
      {
        "--hostname", getTestHost(),
        "--port", String.valueOf(getTestPort()),
        "--bindDN", getTestBindDN(),
        "--bindPassword", getTestBindPassword()
      };

      ResultCode resultCode = SubtreeAccessibility.main(args, null, null);
      assertEquals(resultCode, ResultCode.SUCCESS);


      // Use the tool to create a new subtree accessibility restriction.
      args = new String[]
      {
        "--hostname", getTestHost(),
        "--port", String.valueOf(getTestPort()),
        "--bindDN", getTestBindDN(),
        "--bindPassword", getTestBindPassword(),
        "--set",
        "--baseDN", "ou=subtree," + getTestBaseDN(),
        "--state", "read-only-bind-allowed",
        "--bypassUserDN", "uid=bypass," + getTestBaseDN()
      };

      resultCode = SubtreeAccessibility.main(args, null, null);
      assertEquals(resultCode, ResultCode.SUCCESS);


      // Verify that the server now has a restriction defined.
      getResult = (GetSubtreeAccessibilityExtendedResult)
           conn.processExtendedOperation(
                new GetSubtreeAccessibilityExtendedRequest());
      assertResultCodeEquals(getResult, ResultCode.SUCCESS);
      assertNotNull(getResult.getAccessibilityRestrictions());
      assertFalse(getResult.getAccessibilityRestrictions().isEmpty());


      // Verify that we can use the tool in "get" mode with a restriction
      // defined.
      args = new String[]
      {
        "--hostname", getTestHost(),
        "--port", String.valueOf(getTestPort()),
        "--bindDN", getTestBindDN(),
        "--bindPassword", getTestBindPassword()
      };

      resultCode = SubtreeAccessibility.main(args, null, null);
      assertEquals(resultCode, ResultCode.SUCCESS);


      // Use the tool to modify the subtree accessibility restriction.
      args = new String[]
      {
        "--hostname", getTestHost(),
        "--port", String.valueOf(getTestPort()),
        "--bindDN", getTestBindDN(),
        "--bindPassword", getTestBindPassword(),
        "--set",
        "--baseDN", "ou=subtree," + getTestBaseDN(),
        "--state", "read-only-bind-denied",
        "--bypassUserDN", "uid=bypass," + getTestBaseDN()
      };

      resultCode = SubtreeAccessibility.main(args, null, null);
      assertEquals(resultCode, ResultCode.SUCCESS);


      // Verify that the server still has only one restriction defined.
      getResult = (GetSubtreeAccessibilityExtendedResult)
           conn.processExtendedOperation(
                new GetSubtreeAccessibilityExtendedRequest());
      assertResultCodeEquals(getResult, ResultCode.SUCCESS);
      assertNotNull(getResult.getAccessibilityRestrictions());
      assertEquals(getResult.getAccessibilityRestrictions().size(), 1);


      // Use the tool to add a second restriction.
      args = new String[]
      {
        "--hostname", getTestHost(),
        "--port", String.valueOf(getTestPort()),
        "--bindDN", getTestBindDN(),
        "--bindPassword", getTestBindPassword(),
        "--set",
        "--baseDN", "ou=subtree2," + getTestBaseDN(),
        "--state", "hidden"
      };

      resultCode = SubtreeAccessibility.main(args, null, null);
      assertEquals(resultCode, ResultCode.SUCCESS);


      // Verify that the server now has two restrictions defined.
      getResult = (GetSubtreeAccessibilityExtendedResult)
           conn.processExtendedOperation(
                new GetSubtreeAccessibilityExtendedRequest());
      assertResultCodeEquals(getResult, ResultCode.SUCCESS);
      assertNotNull(getResult.getAccessibilityRestrictions());
      assertEquals(getResult.getAccessibilityRestrictions().size(), 2);


      // Verify that we can use the tool in "get" mode with multiple
      // restrictions defined.
      args = new String[]
      {
        "--hostname", getTestHost(),
        "--port", String.valueOf(getTestPort()),
        "--bindDN", getTestBindDN(),
        "--bindPassword", getTestBindPassword()
      };

      resultCode = SubtreeAccessibility.main(args, null, null);
      assertEquals(resultCode, ResultCode.SUCCESS);


      // Use the tool to remove the first subtree accessibility restriction.
      args = new String[]
      {
        "--hostname", getTestHost(),
        "--port", String.valueOf(getTestPort()),
        "--bindDN", getTestBindDN(),
        "--bindPassword", getTestBindPassword(),
        "--set",
        "--baseDN", "ou=subtree," + getTestBaseDN(),
        "--state", "accessible"
      };

      resultCode = SubtreeAccessibility.main(args, null, null);
      assertEquals(resultCode, ResultCode.SUCCESS);


      // Verify that the server no longer has any restrictions defined.
      getResult = (GetSubtreeAccessibilityExtendedResult)
           conn.processExtendedOperation(
                new GetSubtreeAccessibilityExtendedRequest());
      assertResultCodeEquals(getResult, ResultCode.SUCCESS);
      assertNotNull(getResult.getAccessibilityRestrictions());
      assertEquals(getResult.getAccessibilityRestrictions().size(), 1);


      // Use the tool to remove the remaining subtree accessibility restriction.
      args = new String[]
      {
        "--hostname", getTestHost(),
        "--port", String.valueOf(getTestPort()),
        "--bindDN", getTestBindDN(),
        "--bindPassword", getTestBindPassword(),
        "--set",
        "--baseDN", "ou=subtree2," + getTestBaseDN(),
        "--state", "accessible"
      };

      resultCode = SubtreeAccessibility.main(args, null, null);
      assertEquals(resultCode, ResultCode.SUCCESS);


      // Verify that the server no longer has any restrictions defined.
      getResult = (GetSubtreeAccessibilityExtendedResult)
           conn.processExtendedOperation(
                new GetSubtreeAccessibilityExtendedRequest());
      assertResultCodeEquals(getResult, ResultCode.SUCCESS);
      assertNotNull(getResult.getAccessibilityRestrictions());
      assertTrue(getResult.getAccessibilityRestrictions().isEmpty());


      // Invoke the tool in get mode with the wrong password so it will fail.
      args = new String[]
      {
        "--hostname", getTestHost(),
        "--port", String.valueOf(getTestPort()),
        "--bindDN", getTestBindDN(),
        "--bindPassword", "wrong-" + getTestBindPassword()
      };

      resultCode = SubtreeAccessibility.main(args, null, null);
      assertFalse(resultCode == ResultCode.SUCCESS);


      // Invoke the tool in set mode with a bad base DN so it will fail.
      args = new String[]
      {
        "--hostname", getTestHost(),
        "--port", String.valueOf(getTestPort()),
        "--bindDN", getTestBindDN(),
        "--bindPassword", getTestBindPassword(),
        "--set",
        "--baseDN", "dc=does,dc=not,dc=exist",
        "--state", "accessible"
      };

      resultCode = SubtreeAccessibility.main(args, null, null);
      assertFalse(resultCode == ResultCode.SUCCESS);


      // Invoke the tool in get mode with no credentials so it will fail.
      args = new String[]
      {
        "--hostname", getTestHost(),
        "--port", String.valueOf(getTestPort()),
        "--bindDN", "",
        "--bindPassword", ""
      };

      resultCode = SubtreeAccessibility.main(args, null, null);
      assertFalse(resultCode == ResultCode.SUCCESS);


      // Invoke the tool in get mode with no credentials so it will fail.
      args = new String[]
      {
        "--hostname", getTestHost(),
        "--port", String.valueOf(getTestPort()),
        "--bindDN", "",
        "--bindPassword", "",
        "--set",
        "--baseDN", "ou=subtree,dc=example,dc=com",
        "--state", "accessible"
      };

      resultCode = SubtreeAccessibility.main(args, null, null);
      assertFalse(resultCode == ResultCode.SUCCESS);
    }
    finally
    {
      try
      {
        conn.delete(getTestBaseDN());
      } catch (final Exception e) {}

      conn.close();
    }
  }
}
