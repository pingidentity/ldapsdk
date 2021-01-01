/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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



import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.args.ArgumentParser;



/**
 * This class provides a set of test cases for the deliver-password-reset-token
 * tool.
 */
public final class DeliverPasswordResetTokenTestCase
       extends LDAPSDKTestCase
{
  /**
   * Test a number of methods that don't require actually invoking the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicMethods()
         throws Exception
  {
    final DeliverPasswordResetToken tool =
         new DeliverPasswordResetToken(null, null);

    assertNotNull(tool.getToolName());
    assertEquals(tool.getToolName(), "deliver-password-reset-token");

    assertNotNull(tool.getToolDescription());

    final ArgumentParser parser =
         new ArgumentParser(tool.getToolName(), tool.getToolDescription());
    assertTrue(parser.getNamedArguments().isEmpty());

    tool.addNonLDAPArguments(parser);
    assertFalse(parser.getNamedArguments().isEmpty());

    assertNotNull(tool.getToolVersion());

    assertNotNull(tool.getExampleUsages());

    assertTrue(tool.supportsInteractiveMode());
    assertTrue(tool.defaultsToInteractiveMode());
  }



  /**
   * Tests the behavior when trying to run the tool without any preferred
   * delivery mechanisms.  The tool won't run successfully since the server
   * doesn't know about the extended operation, but this will provide test
   * coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutPreferredDeliveryMechanisms()
         throws Exception
  {
    final InMemoryDirectoryServer testDS = getTestDS();

    final String[] args =
    {
      "--hostname", "localhost",
      "--port", String.valueOf(testDS.getListenPort()),
      "--bindDN", "uid=password.admin,ou=People,dc=example,dc=com",
      "--bindPassword", "password",
      "--userDN", "uid=test.user,ou=People,dc=example,dc=com"
    };

    assertFalse(DeliverPasswordResetToken.main(args, null, null).equals(
         ResultCode.SUCCESS));
  }



  /**
   * Tests the behavior when trying to run the tool with a set of preferred
   * delivery mechanisms.  The tool won't run successfully since the server
   * doesn't know about the extended operation, but this will provide test
   * coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithPreferredDeliveryMechanisms()
         throws Exception
  {
    final InMemoryDirectoryServer testDS = getTestDS();

    final String[] args =
    {
      "--hostname", "localhost",
      "--port", String.valueOf(testDS.getListenPort()),
      "--bindDN", "uid=password.admin,ou=People,dc=example,dc=com",
      "--bindPassword", "password",
      "--userDN", "uid=test.user,ou=People,dc=example,dc=com",
      "--preferredDeliveryMechanism", "SMS",
      "--preferredDeliveryMechanism", "E-Mail"
    };

    assertFalse(DeliverPasswordResetToken.main(args, null, null).equals(
         ResultCode.SUCCESS));
  }



  /**
   * Tests the behavior when the tool is unable to establish a connection to the
   * target server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnableToConnect()
         throws Exception
  {
    final InMemoryDirectoryServer testDS = getTestDS();
    final int listenPort = testDS.getListenPort();
    testDS.shutDown(true);

    try
    {
      final String[] args =
      {
        "--hostname", "localhost",
        "--port", String.valueOf(listenPort),
        "--bindDN", "uid=password.admin,ou=People,dc=example,dc=com",
        "--bindPassword", "password",
        "--userDN", "uid=test.user,ou=People,dc=example,dc=com",
        "--deliveryMechanism", "SMS",
        "--deliveryMechanism", "E-Mail"
      };

      assertFalse(DeliverPasswordResetToken.main(args, null, null).equals(
           ResultCode.SUCCESS));
    }
    finally
    {
      testDS.startListening();
    }
  }



  /**
   * Tests the behavior for a request that should complete successfully and
   * should include a recipient ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessWithRecipientID()
         throws Exception
  {
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.addExtendedOperationHandler(
         new TestDeliverPasswordResetTokenExtendedOperationHandler());
    config.addAdditionalBindCredentials(
         "uid=password.admin,ou=People,dc=example,dc=com", "password");

    final InMemoryDirectoryServer testDS = new InMemoryDirectoryServer(config);
    testDS.startListening();

    try
    {
      final String[] args =
      {
        "--hostname", "localhost",
        "--port", String.valueOf(testDS.getListenPort()),
        "--bindDN", "uid=password.admin,ou=People,dc=example,dc=com",
        "--bindPassword", "password",
        "--userDN", "uid=test.user,ou=People,dc=example,dc=com",
        "--deliveryMechanism", "SMS"
      };

      assertEquals(DeliverPasswordResetToken.main(args, null, null),
           ResultCode.SUCCESS);
    }
    finally
    {
      testDS.shutDown(true);
    }
  }



  /**
   * Tests the behavior for a request that should complete successfully and
   * does not include a recipient ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessWithoutRecipientID()
         throws Exception
  {
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.addExtendedOperationHandler(
         new TestDeliverPasswordResetTokenExtendedOperationHandler());
    config.addAdditionalBindCredentials(
         "uid=password.admin,ou=People,dc=example,dc=com", "password");

    final InMemoryDirectoryServer testDS = new InMemoryDirectoryServer(config);
    testDS.startListening();

    try
    {
      final String[] args =
      {
        "--hostname", "localhost",
        "--port", String.valueOf(testDS.getListenPort()),
        "--bindDN", "uid=password.admin,ou=People,dc=example,dc=com",
        "--bindPassword", "password",
        "--userDN", "uid=test.user,ou=People,dc=example,dc=com"
      };

      assertEquals(DeliverPasswordResetToken.main(args, null, null),
           ResultCode.SUCCESS);
    }
    finally
    {
      testDS.shutDown(true);
    }
  }



  /**
   * Tests the behavior for a request that should fail because it request an
   * unsupported delivery mechanism.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailUnsupportedDeliveryMechanism()
         throws Exception
  {
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.addExtendedOperationHandler(
         new TestDeliverPasswordResetTokenExtendedOperationHandler());
    config.addAdditionalBindCredentials(
         "uid=password.admin,ou=People,dc=example,dc=com", "password");

    final InMemoryDirectoryServer testDS = new InMemoryDirectoryServer(config);
    testDS.startListening();

    try
    {
      final String[] args =
      {
        "--hostname", "localhost",
        "--port", String.valueOf(testDS.getListenPort()),
        "--bindDN", "uid=password.admin,ou=People,dc=example,dc=com",
        "--bindPassword", "password",
        "--userDN", "uid=test.user,ou=People,dc=example,dc=com",
        "--deliveryMechanism", "Unsupported"
      };

      assertEquals(DeliverPasswordResetToken.main(args, null, null),
           ResultCode.UNWILLING_TO_PERFORM);
    }
    finally
    {
      testDS.shutDown(true);
    }
  }
}
