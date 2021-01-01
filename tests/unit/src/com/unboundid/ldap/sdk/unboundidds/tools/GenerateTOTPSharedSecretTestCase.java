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



import java.io.ByteArrayOutputStream;
import java.io.File;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            GenerateTOTPSharedSecretExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            TestTOTPSharedSecretExtendedOperationHandler;
import com.unboundid.util.PasswordReaderHelper;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the generate-totp-shared-secret
 * tool.
 */
public final class GenerateTOTPSharedSecretTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides coverage for methods that can be invoked without running the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToolMethods()
         throws Exception
  {
    final GenerateTOTPSharedSecret tool =
         new GenerateTOTPSharedSecret(null, null);

    assertNotNull(tool.getToolName());
    assertEquals(tool.getToolName(), "generate-totp-shared-secret");

    assertNotNull(tool.getToolDescription());

    assertNotNull(tool.getToolVersion());

    assertTrue(tool.supportsInteractiveMode());

    assertTrue(tool.defaultsToInteractiveMode());

    assertTrue(tool.supportsPropertiesFile());

    assertTrue(tool.supportsOutputFile());

    assertTrue(tool.supportsAuthentication());

    assertTrue(tool.defaultToPromptForBindPassword());

    assertTrue(tool.supportsSASLHelp());

    assertTrue(tool.includeAlternateLongIdentifiers());

    assertNotNull(tool.getExampleUsages());
    assertEquals(tool.getExampleUsages().size(), 2);
  }



  /**
   * Provides test coverage for the ability to get usage information for the
   * tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetUsage()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         GenerateTOTPSharedSecret.main(out, out, "--help"),
         ResultCode.SUCCESS);
  }



  /**
   * Provides test coverage for the use cases in which shared secrets can be
   * generated and revoked successfully.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulOperations()
         throws Exception
  {
    // Get an in-memory directory server instance with support for the
    // generate and revoke TOTP shared secret operations.
    final InMemoryDirectoryServer ds =
         TestTOTPSharedSecretExtendedOperationHandler.getDSWithSupport();

    try
    {
      // Add test data to the in-memory directory server.
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
           "dn: uid=test.user,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: test.user",
           "givenName: Test",
           "sn: User",
           "cn: Test User",
           "userPassword: password");


      // Generate three shared secrets for the test user.
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      assertEquals(
           GenerateTOTPSharedSecret.main(out, out,
                "--hostname", "127.0.0.1",
                "--port", String.valueOf(ds.getListenPort()),
                "--authID", "u:test.user",
                "--userPassword", "password"),
           ResultCode.SUCCESS);
      final String sharedSecret1 = extractSharedSecret(out);
      assertNotNull(sharedSecret1);

      out = new ByteArrayOutputStream();
      assertEquals(
           GenerateTOTPSharedSecret.main(out, out,
                "--hostname", "127.0.0.1",
                "--port", String.valueOf(ds.getListenPort()),
                "--authID", "u:test.user",
                "--userPassword", "password"),
           ResultCode.SUCCESS);
      final String sharedSecret2 = extractSharedSecret(out);
      assertNotNull(sharedSecret2);
      assertFalse(sharedSecret2.equals(sharedSecret1));

      out = new ByteArrayOutputStream();
      assertEquals(
           GenerateTOTPSharedSecret.main(out, out,
                "--hostname", "127.0.0.1",
                "--port", String.valueOf(ds.getListenPort()),
                "--authID", "u:test.user",
                "--userPassword", "password"),
           ResultCode.SUCCESS);
      final String sharedSecret3 = extractSharedSecret(out);
      assertNotNull(sharedSecret3);
      assertFalse(sharedSecret3.equals(sharedSecret1));
      assertFalse(sharedSecret3.equals(sharedSecret2));


      // Revoke the second shared secret.
      final File passwordFile = createTempFile("password");

      out = new ByteArrayOutputStream();
      assertEquals(
           GenerateTOTPSharedSecret.main(out, out,
                "--hostname", "127.0.0.1",
                "--port", String.valueOf(ds.getListenPort()),
                "--authID", "u:test.user",
                "--userPasswordFile", passwordFile.getAbsolutePath(),
                "--revoke", sharedSecret2),
           ResultCode.SUCCESS);


      // Revoke the remaining shared secrets.
      try
      {
        PasswordReaderHelper.setTestPasswordReader("password");
        out = new ByteArrayOutputStream();
        assertEquals(
             GenerateTOTPSharedSecret.main(out, out,
                  "--hostname", "127.0.0.1",
                  "--port", String.valueOf(ds.getListenPort()),
                  "--authID", "u:test.user",
                  "--promptForUserPassword",
                  "--revokeAll"),
             ResultCode.SUCCESS);
      }
      finally
      {
        PasswordReaderHelper.resetTestPasswordReader();
      }
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Provides test coverage for the use cases in which each request fails.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailedOperations()
         throws Exception
  {
    // Get an in-memory directory server instance with support for the
    // generate and revoke TOTP shared secret operations.
    final Schema defaultSchema = Schema.getDefaultStandardSchema();

    final Schema sharedSecretSchema = new Schema(new Entry(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubentry",
         "objectClass: subschema",
         "attributeTypes: ( 1.3.6.1.4.1.30221.2.1.896 " +
              "NAME 'ds-auth-totp-shared-secret' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 " +
              "USAGE directoryOperation " +
              "X-ORIGIN 'UnboundID Directory Server' )"));

    final Schema mergedSchema =
         Schema.mergeSchemas(defaultSchema, sharedSecretSchema);

    final InMemoryDirectoryServerConfig dsConfig =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    final TestTOTPSharedSecretExtendedOperationHandler totpExtopHandler =
         new TestTOTPSharedSecretExtendedOperationHandler();
    dsConfig.addExtendedOperationHandler(totpExtopHandler);

    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/dc=example,dc=com",
      "ldap://ds2.example.com:389/dc=example,dc=com"
    };
    totpExtopHandler.setCannedGenerateResult(
         new GenerateTOTPSharedSecretExtendedResult(1, ResultCode.OTHER,
              "This is the diagnostic message", "dc=matched,dc=com",
              referralURLs, null, new Control("1.2.3.4"),
              new Control("5.6.7.8")));
    totpExtopHandler.setCannedRevokeResult(new ExtendedResult(1,
         ResultCode.OTHER, "This is the diagnostic message",
         "dc=matched,dc=com", referralURLs, null, null, null));

    dsConfig.setSchema(mergedSchema);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsConfig);
    ds.startListening();

    try
    {
      // Fail to generate a shared secret for a user that doesn't exist.
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      ResultCode resultCode = GenerateTOTPSharedSecret.main(out, out,
           "--hostname", "127.0.0.1",
           "--port", String.valueOf(ds.getListenPort()),
           "--authID", "u:test.user",
           "--userPassword", "password");
      assertEquals(resultCode, ResultCode.OTHER);


      // Fail to revoke a shared secret for a user that doesn't exist.
      out = new ByteArrayOutputStream();
      resultCode = GenerateTOTPSharedSecret.main(out, out,
           "--hostname", "127.0.0.1",
           "--port", String.valueOf(ds.getListenPort()),
           "--authID", "u:test.user",
           "--userPassword", "password",
           "--revoke", "abcdefghijklmnop");
      assertEquals(resultCode, ResultCode.OTHER);


      // Fail to revoke all shared secrets for a user that doesn't exist.
      out = new ByteArrayOutputStream();
      resultCode = GenerateTOTPSharedSecret.main(out, out,
           "--hostname", "127.0.0.1",
           "--port", String.valueOf(ds.getListenPort()),
           "--authID", "u:test.user",
           "--userPassword", "password",
           "--revokeAll");
      assertEquals(resultCode, ResultCode.OTHER);
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Provides test coverage for the case in which the tool cannot establish a
   * connection to a directory server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnableToConnect()
         throws Exception
  {
    final InMemoryDirectoryServer ds =
         TestTOTPSharedSecretExtendedOperationHandler.getDSWithSupport();
    final int listenPort = ds.getListenPort();
    ds.shutDown(true);

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
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password");

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ResultCode resultCode = GenerateTOTPSharedSecret.main(out, out,
         "--hostname", "127.0.0.1",
         "--port", String.valueOf(listenPort),
         "--authID", "u:test.user",
         "--userPassword", "password",
         "--revokeAll");
    assertFalse(resultCode == ResultCode.SUCCESS);
  }



  /**
   * Extracts the generated TOTP shared secret from the provided output stream.
   *
   * @param  os  The byte array output stream from which to extract the
   *             generated TOTP shared secret.
   *
   * @return  The extracted TOTP shared secret, or {@code null} if none could be
   *          obtained.
   */
  private static String extractSharedSecret(final ByteArrayOutputStream os)
  {
    final String s = StaticUtils.toUTF8String(os.toByteArray());

    final String prefix = "Successfully generated TOTP shared secret '";
    final int prefixPos = s.indexOf(prefix);
    if (prefixPos < 0)
    {
      return null;
    }

    final int closePos = s.indexOf("'.", prefixPos);
    if (closePos < 0)
    {
      return null;
    }

    return s.substring(prefixPos + prefix.length(), closePos);
  }
}
