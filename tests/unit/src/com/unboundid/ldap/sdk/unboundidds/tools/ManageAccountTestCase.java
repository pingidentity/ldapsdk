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



import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityError;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityNotice;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityWarning;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateOperation;
import com.unboundid.util.Base64;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.args.Argument;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanValueArgument;
import com.unboundid.util.args.StringArgument;
import com.unboundid.util.args.SubCommand;
import com.unboundid.util.args.TimestampArgument;



/**
 * This class provides test coverage for the ManageAccount class.
 */
public final class ManageAccountTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of basic tool methods that can be called without
   * running the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicToolMethods()
         throws Exception
  {
    final ManageAccount tool = new ManageAccount(null, null);

    assertNotNull(tool.getToolName());
    assertEquals(tool.getToolName(), "manage-account");

    assertNotNull(tool.getToolDescription());

    assertNotNull(tool.getToolVersion());

    assertTrue(tool.supportsInteractiveMode());
    assertTrue(tool.defaultsToInteractiveMode());

    assertTrue(tool.supportsPropertiesFile());

    assertTrue(tool.supportsAuthentication());

    assertTrue(tool.supportsSASLHelp());

    assertTrue(tool.defaultToPromptForBindPassword());

    assertTrue(tool.includeAlternateLongIdentifiers());

    assertTrue(tool.supportsMultipleServers());

    assertNotNull(tool.getConnectionOptions());

    assertFalse(tool.cancelRequested());

    assertFalse(tool.allDNsProvided());

    assertFalse(tool.allFiltersProvided());

    assertNotNull(tool.getExampleUsages());
    assertFalse(tool.getExampleUsages().isEmpty());

    tool.handleUnsolicitedNotification(null, null);
  }



  /**
   * Tests the behavior when trying to get usage information for the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHelp()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final String[] args =
    {
      "--help"
    };

    assertEquals(
         ManageAccount.main(out, out, args),
         ResultCode.SUCCESS);

    assertNoMissingMessageTokens(out, args);
  }



  /**
   * Tests the behavior when trying to get usage information about all available
   * subcommands.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHelpSubCommands()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final String[] args =
    {
      "--help-subcommands"
    };

    assertEquals(
         ManageAccount.main(out, out, args),
         ResultCode.SUCCESS);

    assertNoMissingMessageTokens(out, args);
  }



  /**
   * Tests the behavior when trying to get usage information about all available
   * subcommands.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHelpForEachSubCommand()
         throws Exception
  {
    for (final ManageAccountSubCommandType t :
         ManageAccountSubCommandType.values())
    {
      final ByteArrayOutputStream out = new ByteArrayOutputStream();

      final String[] args =
      {
        t.getPrimaryName(),
        "--help"
      };

      assertEquals(
           ManageAccount.main(out, out, args),
           ResultCode.SUCCESS);

      assertNoMissingMessageTokens(out, args);
    }
  }



  /**
   * Tests the behavior when trying to get SASL usage information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHelpSASL()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final String[] args =
    {
      "--help-sasl"
    };

    assertEquals(
         ManageAccount.main(out, out, args),
         ResultCode.SUCCESS);

    assertNoMissingMessageTokens(out, args);
  }



  /**
   * Tests the behavior when trying to run the tool with the
   * --generateSampleRateFile" argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateSampleRateFile()
         throws Exception
  {
    final File outputFile = createTempFile();
    assertTrue(outputFile.exists());
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final String[] args =
    {
      "--generateSampleRateFile", outputFile.getAbsolutePath()
    };

    assertEquals(
         ManageAccount.main(out, out, args),
         ResultCode.SUCCESS);

    assertTrue(outputFile.exists());
  }



  /**
   * Tests the behavior when running the tool and expecting a success result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllSuccessResult()
         throws Exception
  {
    // Get an instance of the manage-account tool that we will run to generate a
    // sample variable rate data file.  Not only can we use this file to get
    // test coverage later, but we can also use the tool instance to get the
    // argument parser available so that we can introspect it to get information
    // about what arguments we can use.
    final String variableRateDataFile = createTempFile().getAbsolutePath();
    final ManageAccount tool = new ManageAccount(null, null);
    assertEquals(
         tool.runTool("--generateSampleRateFile", variableRateDataFile),
         ResultCode.SUCCESS);

    final ArgumentParser parser = tool.getArgumentParser();
    assertNotNull(parser);


    // Create some other files that will be used for testing.
    final String rejectFile = createTempFile().getAbsolutePath();
    final String dnFile = createTempFile(
         "# Comment at the top",
         "uid=user.1,ou=People,dc=example,dc=com",
         "# Comment in the middle. Also, blank line follows.",
         "",
         "uid=user.2,ou=People,dc=example,dc=com",
         "dn:uid=user.3,ou=People,dc=example,dc=com",
         "dn: uid=user.4,ou=People,dc=example,dc=com",
         "dn::" + Base64.encode("uid=user.5,ou=People,dc=example,dc=com"),
         "dn:: " + Base64.encode("uid=user.6,ou=People,dc=example,dc=com"),
         "",
         "# Comment at the end").getAbsolutePath();


    // Create an in-memory directory server instance with fake support for the
    // password policy state extended operation.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/dc=example,dc=com",
      "ldap://ds2.example.com:389/dc=example,dc=com"
    };

    final PasswordPolicyStateOperation[] resultOperations =
    {
      new PasswordPolicyStateOperation(
           PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_DISABLED_STATE,
           new ASN1OctetString[] { new ASN1OctetString("false") }),
      new PasswordPolicyStateOperation(
           PasswordPolicyStateOperation.OP_TYPE_GET_FAILURE_LOCKOUT_TIME,
           null),
      new PasswordPolicyStateOperation(
           PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_USABILITY_NOTICES,
           new ASN1OctetString[]
           {
             new ASN1OctetString(
                  new PasswordPolicyStateAccountUsabilityNotice(
                       PasswordPolicyStateAccountUsabilityNotice.
                            NOTICE_TYPE_IN_MINIMUM_PASSWORD_AGE,
                       PasswordPolicyStateAccountUsabilityNotice.
                            NOTICE_NAME_IN_MINIMUM_PASSWORD_AGE,
                       "notice message").toString()),
             new ASN1OctetString("Notice 2"),
           }),
      new PasswordPolicyStateOperation(
           PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_USABILITY_WARNINGS,
           new ASN1OctetString[]
           {
             new ASN1OctetString(
                  new PasswordPolicyStateAccountUsabilityWarning(
                       PasswordPolicyStateAccountUsabilityWarning.
                            WARNING_TYPE_ACCOUNT_EXPIRING,
                       PasswordPolicyStateAccountUsabilityWarning.
                            WARNING_NAME_ACCOUNT_EXPIRING,
                       "warning message").toString()),
             new ASN1OctetString("Warning 2"),
           }),
      new PasswordPolicyStateOperation(
           PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_USABILITY_ERRORS,
           new ASN1OctetString[]
           {
             new ASN1OctetString(
                  new PasswordPolicyStateAccountUsabilityError(
                       PasswordPolicyStateAccountUsabilityError.
                            ERROR_TYPE_ACCOUNT_EXPIRED,
                       PasswordPolicyStateAccountUsabilityError.
                            ERROR_NAME_ACCOUNT_EXPIRED,
                       "error message").toString()),
             new ASN1OctetString("Error 2"),
           })
    };

    cfg.addExtendedOperationHandler(
         new CannedResponsePWPStateInMemoryExtendedOperationHandler(
              new PasswordPolicyStateExtendedResult(-1, ResultCode.SUCCESS,
                   "Success", "ou=Matched DN,dc=example,dc=com", referralURLs,
                   "uid=test.user,ou=People,dc=example,dc=com",
                   resultOperations, null)));

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    try
    {
      final ArrayList<String> argList = new ArrayList<String>(20);
      final ByteArrayOutputStream out = new ByteArrayOutputStream();
      for (final ManageAccountSubCommandType t :
           ManageAccountSubCommandType.values())
      {
        for (final String name : t.getAllNames())
        {
          argList.clear();
          argList.add(name);
          argList.add("--hostname");
          argList.add("127.0.0.1");
          argList.add("--port");
          argList.add(String.valueOf(ds.getListenPort()));
          argList.add("--targetDN");
          argList.add("uid=test.user,ou=People,dc=example,dc=com");

          final SubCommand sc = parser.getSubCommand(name);
          assertNotNull(sc);

          final ArgumentParser subCommandParser = sc.getArgumentParser();

          final Argument a = subCommandParser.getNamedArgument('O');
          if (a == null)
          {
            String[] args = argList.toArray(StaticUtils.NO_STRINGS);
            assertEquals(
                 ManageAccount.main(out, out, args),
                 ResultCode.SUCCESS,
                 "Failed with arguments " + argList + ":  " +
                      StaticUtils.toUTF8String(out.toByteArray()));

            out.reset();
            args = argList.toArray(StaticUtils.NO_STRINGS);
            assertEquals(
                 ManageAccount.main(out, out, args),
                 ResultCode.SUCCESS,
                 "Failed with arguments " + argList + ":  " +
                      StaticUtils.toUTF8String(out.toByteArray()));

            continue;
          }

          if (! a.isRequired())
          {
            out.reset();
            String[] args = argList.toArray(StaticUtils.NO_STRINGS);
            assertEquals(
                 ManageAccount.main(null, null, args),
                 ResultCode.SUCCESS,
                 "Failed with arguments " + argList + ":  " +
                      StaticUtils.toUTF8String(out.toByteArray()));

            argList.add("--suppressEmptyResultOperations");
            args = argList.toArray(StaticUtils.NO_STRINGS);
            out.reset();
            assertEquals(
                 ManageAccount.main(null, null, args),
                 ResultCode.SUCCESS,
                 "Failed with arguments " + argList + ":  " +
                      StaticUtils.toUTF8String(out.toByteArray()));
            argList.remove(argList.size()-1);
          }

          final String value1;
          final String value2;
          if (a instanceof BooleanValueArgument)
          {
            value1 = "true";
            value2 = "false";
          }
          else if (a instanceof StringArgument)
          {
            if (sc.hasName("set-last-login-ip-address"))
            {
              value1 = "1.2.3.4";
              value2 = "5.6.7.8";
            }
            else
            {
              value1 = "value 1";
              value2 = "value 2";
            }
          }
          else if (a instanceof TimestampArgument)
          {
            final long now = System.currentTimeMillis();
            value1 = StaticUtils.encodeGeneralizedTime(now - 1L);
            value2 = StaticUtils.encodeGeneralizedTime(now);
          }
          else
          {
            throw new AssertionError("Unexpected argument type for argument " +
                 a.getIdentifierString() + " in subcommand " + name + ":  " +
                 a.getClass().getName());
          }

          argList.add("--ratePerSecond");
          argList.add("100");
          argList.add("--variableRateData");
          argList.add(variableRateDataFile);
          argList.add("--rejectFile");
          argList.add(rejectFile);
          argList.add("--targetDNFile");
          argList.add(dnFile);
          argList.add("--numThreads");
          argList.add("10");
          argList.add("--numSearchThreads");
          argList.add("10");

          argList.add(a.getIdentifierString());
          argList.add(value1);

          out.reset();
          String[] args = argList.toArray(StaticUtils.NO_STRINGS);
          assertEquals(
               ManageAccount.main(null, null, args),
               ResultCode.SUCCESS,
                 "Failed with arguments " + argList + ":  " +
                      StaticUtils.toUTF8String(out.toByteArray()));

          out.reset();
          argList.add("--suppressEmptyResultOperations");
          args = argList.toArray(StaticUtils.NO_STRINGS);
          assertEquals(
               ManageAccount.main(null, null, args),
               ResultCode.SUCCESS,
                 "Failed with arguments " + argList + ":  " +
                      StaticUtils.toUTF8String(out.toByteArray()));
          argList.remove(argList.size()-1);

          if (a.getMaxOccurrences() > 1)
          {
            argList.add(a.getIdentifierString());
            argList.add(value2);

            out.reset();
            args = argList.toArray(StaticUtils.NO_STRINGS);
            assertEquals(
                 ManageAccount.main(null, null, args),
                 ResultCode.SUCCESS,
                 "Failed with arguments " + argList + ":  " +
                      StaticUtils.toUTF8String(out.toByteArray()));

            out.reset();
            argList.add("--suppressEmptyResultOperations");
            args = argList.toArray(StaticUtils.NO_STRINGS);
            assertEquals(
                 ManageAccount.main(null, null, args),
                 ResultCode.SUCCESS,
                 "Failed with arguments " + argList + ":  " +
                      StaticUtils.toUTF8String(out.toByteArray()));
            argList.remove(argList.size()-1);
          }
        }
      }
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior when running with arguments used to search for entries
   * rather than specifying them by DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchForEntries()
         throws Exception
  {
    // Get an instance of the manage-account tool that we will run to generate a
    // sample variable rate data file.  Not only can we use this file to get
    // test coverage later, but we can also use the tool instance to get the
    // argument parser available so that we can introspect it to get information
    // about what arguments we can use.
    final String variableRateDataFile = createTempFile().getAbsolutePath();
    final ManageAccount tool = new ManageAccount(null, null);
    assertEquals(
         tool.runTool("--generateSampleRateFile", variableRateDataFile),
         ResultCode.SUCCESS);


    // Create some other files that will be used for testing.
    final String rejectFile = createTempFile().getAbsolutePath();
    final String filterFile = createTempFile(
         "# Comment at the top",
         "(uid=user.1)",
         "# Comment in the middle. Also, blank line follows.",
         "",
         "(uid=user.2)",
         "(uid=user.3)",
         "(mail=user.4@example.com)",
         "",
         "# The following is not a valid filter",
         "this is not a valid filter",
         "",
         "(objectClass=*)",
         "# Comment at the end").getAbsolutePath();
    final String userIDFile = createTempFile(
         "# Comment at the top",
         "user.1",
         "# Comment in the middle. Also, blank line follows.",
         "",
         "user.2",
         "user.3",
         "user.4@example.com",
         "",
         "# Comment at the end").getAbsolutePath();


    // Create an in-memory directory server instance with fake support for the
    // password policy state extended operation.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/dc=example,dc=com",
      "ldap://ds2.example.com:389/dc=example,dc=com"
    };

    final PasswordPolicyStateOperation[] resultOperations =
    {
      new PasswordPolicyStateOperation(
           PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_DISABLED_STATE,
           new ASN1OctetString[] { new ASN1OctetString("false") }),
      new PasswordPolicyStateOperation(
           PasswordPolicyStateOperation.OP_TYPE_GET_FAILURE_LOCKOUT_TIME,
           null),
      new PasswordPolicyStateOperation(
           PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_USABILITY_NOTICES,
           new ASN1OctetString[]
           {
             new ASN1OctetString("Notice 1"),
             new ASN1OctetString("Notice 2"),
             new ASN1OctetString("Notice 3")
           })
    };

    cfg.addExtendedOperationHandler(
         new CannedResponsePWPStateInMemoryExtendedOperationHandler(
              new PasswordPolicyStateExtendedResult(-1, ResultCode.SUCCESS,
                   "Success", "ou=Matched DN,dc=example,dc=com", referralURLs,
                   "uid=test.user,ou=People,dc=example,dc=com",
                   resultOperations, null)));

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    try
    {
      ds.add(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");
      ds.add(
           "dn: ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: People");
      ds.add(
           "dn: uid=user.1,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: user.1",
           "givenName: User",
           "sn: 1",
           "cn: User 1",
           "mail: user.1@example.com");
      ds.add(
           "dn: uid=user.4,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: user.4",
           "givenName: User",
           "sn: 4",
           "cn: User 4",
           "mail: user.4@example.com");

      final ByteArrayOutputStream out = new ByteArrayOutputStream();
      assertEquals(
           ManageAccount.main(out, out,
                "get-all",
                "--hostname", "127.0.0.1",
                "--port", String.valueOf(ds.getListenPort()),
                "--targetFilter", "(uid=user.1)",
                "--targetFilter", "(uid=user.2)",
                "--targetFilter", "(objectClass=*)",
                "--targetFilterFile", filterFile,
                "--targetUserID", "user.1",
                "--targetUserID", "user.2",
                "--targetUserIDFile", userIDFile,
                "--rejectFile", rejectFile,
                "--appendToRejectFile",
                "--numThreads", "10",
                "--numSearchThreads", "10",
                "--variableRateData", variableRateDataFile,
                "--simplePageSize", "1"),
           ResultCode.SUCCESS,
           "manage-account failed with output:  " +
                StaticUtils.toUTF8String(out.toByteArray()));

      out.reset();
      assertEquals(
           ManageAccount.main(out, out,
                "get-all",
                "--hostname", "127.0.0.1",
                "--port", String.valueOf(ds.getListenPort()),
                "--targetFilter", "(uid=user.1)",
                "--targetFilter", "(uid=user.2)",
                "--targetFilter", "(objectClass=*)",
                "--targetFilterFile", filterFile,
                "--targetUserID", "user.1",
                "--targetUserID", "user.2",
                "--targetUserIDFile", userIDFile,
                "--rejectFile", rejectFile,
                "--numThreads", "10",
                "--numSearchThreads", "10",
                "--variableRateData", variableRateDataFile,
                "--baseDN", "ou=missing,dc=example,dc=com"),
           ResultCode.SUCCESS,
           "manage-account failed with output:  " +
                StaticUtils.toUTF8String(out.toByteArray()));

      out.reset();
      assertEquals(
           ManageAccount.main(out, out,
                "get-all",
                "--hostname", "127.0.0.1",
                "--port", String.valueOf(ds.getListenPort()),
                "--targetFilter", "(uid=user.1)",
                "--targetFilter", "(uid=user.2)",
                "--targetFilter", "(objectClass=*)",
                "--targetFilterFile", filterFile,
                "--targetUserID", "user.1",
                "--targetUserID", "user.2",
                "--targetUserIDFile", userIDFile,
                "--rejectFile", rejectFile,
                "--appendToRejectFile",
                "--variableRateData", variableRateDataFile,
                "--baseDN", "ou=missing,dc=example,dc=com",
                "--simplePageSize", "1"),
           ResultCode.SUCCESS,
           "manage-account failed with output:  " +
                StaticUtils.toUTF8String(out.toByteArray()));
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior when the manage-account command will return a failure
   * result that does not indicate that the operation may be retried.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testManageAccountNonRetryableFailures()
         throws Exception
  {
    // Create an in-memory directory server instance with fake support for the
    // password policy state extended operation.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    cfg.addExtendedOperationHandler(
         new CannedResponsePWPStateInMemoryExtendedOperationHandler(
              new PasswordPolicyStateExtendedResult(-1,
                   ResultCode.NO_SUCH_OBJECT, null, null, null, null, null,
                   null)));

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    try
    {
      final ByteArrayOutputStream out = new ByteArrayOutputStream();
      assertEquals(
           ManageAccount.main(out, out,
                "get-all",
                "--hostname", "127.0.0.1",
                "--port", String.valueOf(ds.getListenPort()),
                "--targetDN", "uid=user.0,ou=People,dc=example,dc=com"),
           ResultCode.SUCCESS,
           "manage-account failed with output:  " +
                StaticUtils.toUTF8String(out.toByteArray()));
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior when the manage-account command will return a failure
   * result that does indicate that the operation may be retried.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testManageAccountRetryableFailures()
         throws Exception
  {
    // Create an in-memory directory server instance with fake support for the
    // password policy state extended operation.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    cfg.addExtendedOperationHandler(
         new CannedResponsePWPStateInMemoryExtendedOperationHandler(
              new PasswordPolicyStateExtendedResult(-1,
                   ResultCode.OTHER, null, null, null, null, null,
                   null)));

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    try
    {
      final ByteArrayOutputStream out = new ByteArrayOutputStream();
      assertEquals(
           ManageAccount.main(out, out,
                "get-all",
                "--hostname", "127.0.0.1",
                "--port", String.valueOf(ds.getListenPort()),
                "--targetDN", "uid=user.0,ou=People,dc=example,dc=com"),
           ResultCode.SUCCESS,
           "manage-account failed with output:  " +
                StaticUtils.toUTF8String(out.toByteArray()));
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Ensures that the provided output does not include any replacement tokens
   * that weren't replaced by anything (and therefore show up as something like
   * "{0}" in the output).
   *
   * @param  out   The output to examine.
   * @param  args  The tool arguments used to obtain the output.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void assertNoMissingMessageTokens(
                           final ByteArrayOutputStream out, final String[] args)
          throws Exception
  {
    final BufferedReader reader = new BufferedReader(new InputStreamReader(
         new ByteArrayInputStream(out.toByteArray())));

    try
    {
      while (true)
      {
        final String line = reader.readLine();
        if (line == null)
        {
          return;
        }

        int openCurlyPos = line.indexOf('{');
        while (openCurlyPos >= 0)
        {
          int closeCurlyPos = line.indexOf('}', openCurlyPos);
          if (closeCurlyPos < 0)
          {
            break;
          }

          try
          {
            final int intValue = Integer.parseInt(
                 line.substring((openCurlyPos+1), closeCurlyPos));
            fail("Found un-replaced token {" + intValue + "} in line " + line +
                 " obtained when running manage-account with args " +
                 Arrays.toString(args));
          }
          catch (final Exception e)
          {
            // This is what should have happened.
          }

          openCurlyPos = line.indexOf('{', (openCurlyPos+1));
        }
      }
    }
    finally
    {
      reader.close();
    }
  }
}
