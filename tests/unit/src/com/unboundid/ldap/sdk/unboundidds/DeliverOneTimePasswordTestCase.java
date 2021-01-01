/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.args.ArgumentParser;



/**
 * This class provides a set of test cases for the deliver-one-time-password
 * tool.
 */
public final class DeliverOneTimePasswordTestCase
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
    final DeliverOneTimePassword tool = new DeliverOneTimePassword(null, null);

    assertNotNull(tool.getToolName());
    assertEquals(tool.getToolName(), "deliver-one-time-password");

    assertNotNull(tool.getToolDescription());

    final ArgumentParser parser =
         new ArgumentParser(tool.getToolName(), tool.getToolDescription());
    assertTrue(parser.getNamedArguments().isEmpty());

    tool.addNonLDAPArguments(parser);
    assertFalse(parser.getNamedArguments().isEmpty());

    assertNotNull(tool.getToolVersion());

    assertFalse(tool.supportsAuthentication());

    assertNotNull(tool.getExampleUsages());

    assertTrue(tool.supportsInteractiveMode());
    assertTrue(tool.defaultsToInteractiveMode());
  }



  /**
   * Tests the behavior when trying to run the tool, using a bind DN and a
   * static password provided as an argument.  The tool won't run successfully
   * since the server doesn't know about the extended operation, but this will
   * provide test coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithBindDNAndPasswordArgument()
         throws Exception
  {
    final InMemoryDirectoryServer testDS = getTestDS();

    final String[] args =
    {
      "--hostname", "localhost",
      "--port", String.valueOf(testDS.getListenPort()),
      "--bindDN", "uid=test,ou=People,dc=example,dc=com",
      "--bindPassword", "password"
    };

    assertFalse(DeliverOneTimePassword.main(args, null, null).equals(
         ResultCode.SUCCESS));
  }



  /**
   * Tests the behavior when trying to run the tool, using a username and a
   * static password provided in a file.  Also include a set of delivery
   * mechanisms.  The tool won't run successfully since the server doesn't know
   * about the extended operation, but this will provide test coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithUserNameAndPasswordFile()
         throws Exception
  {
    final InMemoryDirectoryServer testDS = getTestDS();

    final File passwordFile = createTempFile("password");

    final String[] args =
    {
      "--hostname", "localhost",
      "--port", String.valueOf(testDS.getListenPort()),
      "--userName", "test",
      "--bindPasswordFile", passwordFile.getAbsolutePath(),
      "--deliveryMechanism", "SMS",
      "--deliveryMechanism", "E-Mail"
    };

    assertFalse(DeliverOneTimePassword.main(args, null, null).equals(
         ResultCode.SUCCESS));
  }



  /**
   * Tests the behavior when trying to run the tool, using a username and an
   * empty password file.  The tool won't run successfully since the server
   * doesn't know about the extended operation, but this will provide test
   * coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithUserNameAndEmptyPasswordFile()
         throws Exception
  {
    final InMemoryDirectoryServer testDS = getTestDS();

    final File passwordFile = createTempFile();

    final String[] args =
    {
      "--hostname", "localhost",
      "--port", String.valueOf(testDS.getListenPort()),
      "--userName", "test",
      "--bindPasswordFile", passwordFile.getAbsolutePath(),
      "--deliveryMechanism", "SMS",
      "--deliveryMechanism", "E-Mail"
    };

    assertFalse(DeliverOneTimePassword.main(args, null, null).equals(
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
        "--userName", "test",
        "--bindPassword", "password",
        "--deliveryMechanism", "SMS",
        "--deliveryMechanism", "E-Mail"
      };

      assertFalse(DeliverOneTimePassword.main(args, null, null).equals(
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
         new TestDeliverOTPExtendedOperationHandler());

    final InMemoryDirectoryServer testDS = new InMemoryDirectoryServer(config);
    testDS.startListening();

    try
    {
      final String[] args =
      {
        "--hostname", "localhost",
        "--port", String.valueOf(testDS.getListenPort()),
        "--bindDN", "uid=test,ou=People,dc=example,dc=com",
        "--bindPassword", "password",
        "--deliveryMechanism", "SMS"
      };

      assertEquals(DeliverOneTimePassword.main(args, null, null),
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
         new TestDeliverOTPExtendedOperationHandler());

    final InMemoryDirectoryServer testDS = new InMemoryDirectoryServer(config);
    testDS.startListening();

    try
    {
      final String[] args =
      {
        "--hostname", "localhost",
        "--port", String.valueOf(testDS.getListenPort()),
        "--bindDN", "uid=test,ou=People,dc=example,dc=com",
        "--bindPassword", "password"
      };

      assertEquals(DeliverOneTimePassword.main(args, null, null),
           ResultCode.SUCCESS);
    }
    finally
    {
      testDS.shutDown(true);
    }
  }
}
