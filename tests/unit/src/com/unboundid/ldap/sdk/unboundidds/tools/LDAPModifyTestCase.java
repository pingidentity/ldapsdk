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



import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.zip.GZIPOutputStream;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.extensions.NoticeOfDisconnectionExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.controls.PasswordUpdateBehaviorRequestControl;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StartAdministrativeSessionInMemoryExtendedOperationHandler;
import com.unboundid.util.Base64;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.PassphraseEncryptedOutputStream;
import com.unboundid.util.PasswordReader;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the LDAPModify tool.
 */
public final class LDAPModifyTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the methods that can be covered without actually
   * running the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGeneralToolMethods()
         throws Exception
  {
    final LDAPModify tool = new LDAPModify(null, null, null);

    assertNotNull(tool.getToolName());
    assertEquals(tool.getToolName(), "ldapmodify");

    assertNotNull(tool.getToolDescription());

    assertNotNull(tool.getToolVersion());

    assertTrue(tool.supportsInteractiveMode());

    assertTrue(tool.defaultsToInteractiveMode());

    assertTrue(tool.supportsPropertiesFile());

    assertTrue(tool.defaultToPromptForBindPassword());

    assertTrue(tool.includeAlternateLongIdentifiers());

    assertNotNull(tool.getExampleUsages());
    assertFalse(tool.getExampleUsages().isEmpty());

    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();
    tool.handleUnsolicitedNotification(conn,
         new NoticeOfDisconnectionExtendedResult(ResultCode.SERVER_DOWN,
              "The server is shutting down"));
    conn.close();
  }



  /**
   * Provides test coverage for the methods used to obtain tool usage
   * information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsage()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out, "--help"),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));

    out.reset();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out, "--helpSASL"),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Tests the behavior of the tool when processing operations read from
   * standard input.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicOperationsReadFromStandardInput()
         throws Exception
  {
    // Get an in-memory directory server instance to use for testing.
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Verify the initial content of the in-memory directory server.
    final LDAPConnection conn = ds.getConnection();
    assertEntryExists(conn, "dc=example,dc=com");
    assertEntryExists(conn, "ou=People,dc=example,dc=com");
    assertEntryExists(conn, "uid=test.user,ou=People,dc=example,dc=com");
    assertEntryMissing(conn, "ou=new,dc=example,dc=com");
    assertEntryMissing(conn, "ou=Users,dc=example,dc=com");
    assertAttributeMissing(conn, "dc=example,dc=com", "description");


    // Get an input stream with the operations to perform.
    final ByteArrayInputStream in = getInputStream(
         "dn: ou=new,dc=example,dc=com",
         "changeType: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: new",
         "",
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changeType: delete",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: true");


    // Use the ldapmodify tool to apply the changes.  Throw in some other
    // arguments that don't matter in this context and that are hard to test
    // otherwise just to get coverage.
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(in, out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--retryFailedOperations",
              "--ratePerSecond", "1000",
              "--verbose",
              "--characterSet", "UTF-8"),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));


    // Verify the resulting content of the server.
    assertEntryExists(conn, "dc=example,dc=com");
    assertEntryMissing(conn, "ou=People,dc=example,dc=com");
    assertEntryMissing(conn, "uid=test.user,ou=People,dc=example,dc=com");
    assertEntryExists(conn, "ou=new,dc=example,dc=com");
    assertEntryExists(conn, "ou=Users,dc=example,dc=com");
    assertAttributeExists(conn, "dc=example,dc=com", "description");

    conn.close();
  }



  /**
   * Tests the behavior of the tool when processing operations read from a
   * single LDIF file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicOperationsReadFromSingleLDIFFile()
         throws Exception
  {
    // Get an in-memory directory server instance to use for testing.
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Verify the initial content of the in-memory directory server.
    final LDAPConnection conn = ds.getConnection();
    assertEntryExists(conn, "dc=example,dc=com");
    assertEntryExists(conn, "ou=People,dc=example,dc=com");
    assertEntryExists(conn, "uid=test.user,ou=People,dc=example,dc=com");
    assertEntryMissing(conn, "ou=new,dc=example,dc=com");
    assertEntryMissing(conn, "ou=Users,dc=example,dc=com");
    assertAttributeMissing(conn, "dc=example,dc=com", "description");


    // Get an LDIF file with the operations to perform.
    final File ldifFile = createTempFile(
         "dn: ou=new,dc=example,dc=com",
         "changeType: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: new",
         "",
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changeType: delete",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: true");


    // Use the ldapmodify tool to apply the changes.
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--ldifFile", ldifFile.getAbsolutePath()),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));


    // Verify the resulting content of the server.
    assertEntryExists(conn, "dc=example,dc=com");
    assertEntryMissing(conn, "ou=People,dc=example,dc=com");
    assertEntryMissing(conn, "uid=test.user,ou=People,dc=example,dc=com");
    assertEntryExists(conn, "ou=new,dc=example,dc=com");
    assertEntryExists(conn, "ou=Users,dc=example,dc=com");
    assertAttributeExists(conn, "dc=example,dc=com", "description");

    conn.close();
  }



  /**
   * Tests the behavior of the tool when processing operations read from
   * multiple LDIF files.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicOperationsReadFromMultipleLDIFFiles()
         throws Exception
  {
    // Get an in-memory directory server instance to use for testing.
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Verify the initial content of the in-memory directory server.
    final LDAPConnection conn = ds.getConnection();
    assertEntryExists(conn, "dc=example,dc=com");
    assertEntryExists(conn, "ou=People,dc=example,dc=com");
    assertEntryExists(conn, "uid=test.user,ou=People,dc=example,dc=com");
    assertEntryMissing(conn, "ou=new,dc=example,dc=com");
    assertEntryMissing(conn, "ou=Users,dc=example,dc=com");
    assertAttributeMissing(conn, "dc=example,dc=com", "description");


    // Get a set of LDIF files with the operations to perform.
    final File addFile = createTempFile(
         "dn: ou=new,dc=example,dc=com",
         "changeType: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: new");
    final File modifyFile = createTempFile(
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo");
    final File deleteFile = createTempFile(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changeType: delete");
    final File modifyDNFile = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: true");


    // Use the ldapmodify tool to apply the changes.
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--ldifFile", addFile.getAbsolutePath(),
              "--ldifFile", modifyFile.getAbsolutePath(),
              "--ldifFile", deleteFile.getAbsolutePath(),
              "--ldifFile", modifyDNFile.getAbsolutePath()),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));


    // Verify the resulting content of the server.
    assertEntryExists(conn, "dc=example,dc=com");
    assertEntryMissing(conn, "ou=People,dc=example,dc=com");
    assertEntryMissing(conn, "uid=test.user,ou=People,dc=example,dc=com");
    assertEntryExists(conn, "ou=new,dc=example,dc=com");
    assertEntryExists(conn, "ou=Users,dc=example,dc=com");
    assertAttributeExists(conn, "dc=example,dc=com", "description");

    conn.close();
  }



  /**
   * Tests the behavior of the tool when it is not possible to establish a
   * connection.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectFailure()
         throws Exception
  {
    // Get an in-memory directory server instance to use for testing.  Get the
    // listen port and then stop the server.
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final int listenPort = ds.getListenPort();
    ds.shutDown(true);


    // Try to run the tool when the server is offline.
    final ByteArrayInputStream in = getInputStream(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ResultCode resultCode = LDAPModify.main(in, out, out,
         "--hostname", "localhost",
         "--port", String.valueOf(listenPort),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--passwordUpdateBehavior", "is-self-change=true");
    assertFalse((resultCode == ResultCode.SUCCESS),
         new String(out.toByteArray(), "UTF-8"));


    ds.startListening();
  }



  /**
   * Tests the behavior of the tool when it is given the wrong authentication
   * credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthenticationFailure()
         throws Exception
  {
    // Get an in-memory directory server instance to use for testing.
    final InMemoryDirectoryServer ds = getTestDS(true, false);


    // Try to run the tool with the wrong bind password.
    final ByteArrayInputStream in = getInputStream(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ResultCode resultCode = LDAPModify.main(in, out, out,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "wrong");
    assertFalse((resultCode == ResultCode.SUCCESS),
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Tests the behavior of the tool when encountering failed operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOperationFailureWithRejectFile()
         throws Exception
  {
    // Get an in-memory directory server instance to use for testing.
    final InMemoryDirectoryServer ds = getTestDS(true, false);


    // Get a connection to the server and verify the current state.
    final LDAPConnection conn = ds.getConnection();
    assertEntryExists(conn, "dc=example,dc=com");
    assertEntryMissing(conn, "ou=missing,dc=example,dc=com");
    assertAttributeMissing(conn, "dc=example,dc=com", "description");


    // Create an LDIF file with three changes.  The first and third will be
    // valid, and the second will be invalid.
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: before",
         "",
         "dn: ou=missing,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: missing",
         "",
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: after");


    // Create a reject file.
    final File rejectFile = createTempFile();
    assertTrue(rejectFile.delete());


    // Run the tool without the continue on error flag.
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    ResultCode resultCode = LDAPModify.main(getInputStream(), out, out,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--ldifFile", ldifFile.getAbsolutePath(),
         "--rejectFile", rejectFile.getAbsolutePath());
    assertEquals(resultCode, ResultCode.NO_SUCH_OBJECT,
         new String(out.toByteArray(), "UTF-8"));


    // Make sure that the dc=example,dc=com description matches the value set
    // before the failure.
    assertValueExists(conn, "dc=example,dc=com", "description", "before");


    // Make sure that the reject file was updated with the failed change.
    assertTrue(rejectFile.exists());
    assertTrue(rejectFile.length() > 0L);
    assertTrue(rejectFile.delete());


    // Run the tool with the continue on error flag.
    out.reset();
    resultCode = LDAPModify.main(getInputStream(), out, out,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--ldifFile", ldifFile.getAbsolutePath(),
         "--rejectFile", rejectFile.getAbsolutePath(),
         "--continueOnError");
    assertEquals(resultCode, ResultCode.NO_SUCH_OBJECT,
         new String(out.toByteArray(), "UTF-8"));


    // Make sure that the dc=example,dc=com description matches the value set
    // after the failure.
    assertValueExists(conn, "dc=example,dc=com", "description", "after");


    // Make sure that the reject file was updated with the failed change.
    assertTrue(rejectFile.exists());
    assertTrue(rejectFile.length() > 0L);
    assertTrue(rejectFile.delete());


    conn.close();
  }



  /**
   * Tests the behavior of the tool with regard to illegal trailing spaces.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStripTrailingSpaces()
         throws Exception
  {
    // Get an in-memory directory server instance to use for testing.
    final InMemoryDirectoryServer ds = getTestDS(true, false);


    // Create an LDIF file with illegal trailing spaces.
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com ",
         "changetype: modify ",
         "replace: description ",
         "description: foo ");


    // Create a reject file to use to hold rejected changes.
    final File rejectFile = createTempFile();
    assertTrue(rejectFile.delete());


    // Run the tool without the strip trailing spaces flag and verify that the
    // change is rejected./
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    LDAPModify.main(getInputStream(), out, out,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--ldifFile", ldifFile.getAbsolutePath(),
         "--rejectFile", rejectFile.getAbsolutePath());
    assertTrue((rejectFile.exists() && (rejectFile.length() > 0)),
         new String(out.toByteArray(), "UTF-8"));


    // Run the tool with the strip trailing spaces flag and verify that it
    // succeeds.
    out.reset();
    assertTrue(rejectFile.delete());
    LDAPModify.main(getInputStream(), out, out,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--ldifFile", ldifFile.getAbsolutePath(),
         "--rejectFile", rejectFile.getAbsolutePath(),
         "--stripTrailingSpaces");
    assertFalse((rejectFile.exists() && (rejectFile.length() > 0)),
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Provides test coverage for the --dryRun argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDryRun()
         throws Exception
  {
    // Get an in-memory directory server instance to use for testing.  Get the
    // listen port and then stop the server.
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final int listenPort = ds.getListenPort();
    ds.shutDown(true);


    // Get an input stream with the operations to perform.
    final ByteArrayInputStream in = getInputStream(
         "dn: ou=new,dc=example,dc=com",
         "changeType: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: new",
         "",
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changeType: delete",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: true",
         "",
         "dn: ou=Users,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=People",
         "deleteOldRDN: true",
         "newSuperior: dc=example,dc=com");


    // Use the ldapmodify tool to process the changes.  Even though the
    // directory server is offline, the tool should succeed because the --dryRun
    // argument is present.
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(in, out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(listenPort),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--dryRun"),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));


    ds.startListening();
  }



  /**
   * Provides test coverage for the --defaultAdd argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultAdd()
         throws Exception
  {
    // Get an in-memory directory server instance to use for testing.
    final InMemoryDirectoryServer ds = getTestDS(true, false);


    // Create an LDIF file with the entry to add.
    final File ldifFile = createTempFile(
         "dn: ou=new,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: new");


    // Create a reject file that will hold information about any rejected
    // changes.
    final File rejectFile = createTempFile();
    assertTrue(rejectFile.delete());


    // Use the ldapmodify tool to process the change without the --defaultAdd
    // argument and verify that the operation is rejected.
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    LDAPModify.main(getInputStream(), out, out,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--ldifFile", ldifFile.getAbsolutePath(),
         "--rejectFile", rejectFile.getAbsolutePath());
    assertTrue((rejectFile.exists() && (rejectFile.length() > 0)),
         new String(out.toByteArray(), "UTF-8"));


    // Run the same command with the --defaultAdd argument and verify that it
    // succeeds.
    out.reset();
    assertTrue(rejectFile.delete());
    LDAPModify.main(getInputStream(), out, out,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--ldifFile", ldifFile.getAbsolutePath(),
         "--rejectFile", rejectFile.getAbsolutePath(),
         "--defaultAdd");
    assertFalse((rejectFile.exists() && (rejectFile.length() > 0)),
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Provides test coverage for the --followReferrals and --useManageDsaIT
   * arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReferrals()
         throws Exception
  {
    // Create two in-memory directory server instances.  One will hold the data
    // and the other a referral.
    final InMemoryDirectoryServer ds1 =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds1.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds1.startListening();

    final InMemoryDirectoryServer ds2 =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds2.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "dc: example",
         "ref: ldap://localhost:" + ds1.getListenPort() + "/dc=example,dc=com");
    ds2.startListening();


    // Create an LDIF file with the change to attempt.
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");


    // Verify that an attempt to modify the dc=example,dc=com entry in ds2 with
    // neither the --followReferrals nor the --useManageDsaIT arguments will
    // return a referral result.
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds2.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath()),
         ResultCode.REFERRAL,
         new String(out.toByteArray(), "UTF-8"));


    // Verify that an attempt to modify the dc=example,dc=com entry in ds2 with
    // the --useManageDsaIT argument will cause the change to be reflected only
    // in ds2.
    out.reset();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds2.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--useManageDsaIT"),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));
    ds1.assertAttributeMissing("dc=example,dc=com", "description");
    ds2.assertAttributeExists("dc=example,dc=com", "description");


    // Verify that an attempt to modify the dc=example,dc=com entry in ds2 with
    // the --followReferrals argument will cause the operation to be referred to
    // ds1 so the change will be visible there.
    out.reset();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds2.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--followReferrals"),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));
    ds1.assertAttributeExists("dc=example,dc=com", "description");
    ds2.assertAttributeExists("dc=example,dc=com", "description");


    ds1.shutDown(true);
    ds2.shutDown(true);
  }



  /**
   * Provides test coverage for the --useAdministrativeSession argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUseAdministrativeSession()
         throws Exception
  {
    // Create an in-memory directory server instance with support for the
    // start administrative session extended operation.
    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.addExtendedOperationHandler(
         new StartAdministrativeSessionInMemoryExtendedOperationHandler(
              new ExtendedResult(1, ResultCode.SUCCESS, null, null, null, null,
                   null, null)));
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds.startListening();


    // Process a change using an administrative session.
    final ByteArrayInputStream in = getInputStream(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(in, out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--useAdministrativeSession"),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));

    ds.shutDown(true);
  }



  /**
   * Provides test coverage for the --useTransaction argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUseTransaction()
         throws Exception
  {
    // The in-memory directory server has support for transactions by default.
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Process a set of changes in a transaction.
    final ByteArrayInputStream in = getInputStream(
         "dn: ou=new,dc=example,dc=com",
         "changeType: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: new",
         "",
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changeType: delete",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: true");
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(in, out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--useTransaction"),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Provides test coverage for the --useMultiUpdate argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUseMultiUpdate()
         throws Exception
  {
    // The in-memory directory server doesn't have support for multi-update
    // operations, but we can still use it to get coverage.
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Process a set of changes in a transaction.
    final ByteArrayInputStream in = getInputStream(
         "dn: ou=new,dc=example,dc=com",
         "changeType: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: new",
         "",
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changeType: delete",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: true");
    LDAPModify.main(in, null, null,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--multiUpdateErrorBehavior", "atomic");
  }



  /**
   * Provides test coverage for the --assertionFilter argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAssertionControl()
         throws Exception
  {
    // The in-memory directory server supports the assertion control.
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Test all types of operations, none of which will match the assertion
    // filter.
    final ByteArrayInputStream in = getInputStream(
         "dn: ou=test,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: delete",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: userPassword",
         "userPassword: password",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: cn=Test User",
         "deleteOldRDN: false");
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(in, out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--assertionFilter", "(description=bar)",
              "--continueOnError"),
         ResultCode.ASSERTION_FAILED,
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Provides test coverage for the --authorizationIdentity argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthorizationIdentityControl()
         throws Exception
  {
    // The in-memory directory server supports the authorization identity
    // control.
    final InMemoryDirectoryServer ds = getTestDS(true, false);


    // We can't easily test that the authorization identity control was
    // included in the request, but we can at least get coverage for it.
    final ByteArrayInputStream in = getInputStream(
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo");
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(in, out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--authorizationIdentity"),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Provides test coverage for the --noOperation argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoOperationControl()
         throws Exception
  {
    // The in-memory directory server supports the no-operation control.
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Test all types of operations.
    final ByteArrayInputStream in = getInputStream(
         "dn: ou=test,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: delete",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: userPassword",
         "userPassword: password",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: cn=Test User",
         "deleteOldRDN: false");
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(in, out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--noOperation",
              "--continueOnError"),
         ResultCode.NO_OPERATION,
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Provides test coverage for the --permissiveModify argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPermissiveModifyControl()
         throws Exception
  {
    // The in-memory directory server supports the permissive modify control.
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Create an LDIF file with a change to add a value that already exists.
    final File ldifFile = createTempFile(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changeType: modify",
         "add: givenName",
         "givenName: Test");


    // Verify that the attempt to process the change will fail without the
    // permissive modify control.
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--ldifFile", ldifFile.getAbsolutePath()),
         ResultCode.ATTRIBUTE_OR_VALUE_EXISTS,
         new String(out.toByteArray(), "UTF-8"));


    // Verify that the change will succeed with the permissive modify control.
    out.reset();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--permissiveModify"),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Provides test coverage for the --preReadAttribute and --postReadAttribute
   * arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadEntryControls()
         throws Exception
  {
    // The in-memory directory server supports the read entry controls.
    final InMemoryDirectoryServer ds = getTestDS(true, false);


    // We can't easily test that the appropriate response controls were
    // included in the request, but we can at least get coverage for them.
    final ByteArrayInputStream in = getInputStream(
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo");
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(in, out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--preReadAttribute", "*",
              "--preReadAttribute", "+",
              "--postReadAttribute", "*",
              "--postReadAttribute", "+"),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Provides test coverage for the --preReadAttribute and --postReadAttribute
   * arguments when the attribute lists are comma-delimited.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadEntryControlsCommaDelimitedAttrLists()
         throws Exception
  {
    // The in-memory directory server supports the read entry controls.
    final InMemoryDirectoryServer ds = getTestDS(true, false);


    // We can't easily test that the appropriate response controls were
    // included in the request, but we can at least get coverage for them.
    final ByteArrayInputStream in = getInputStream(
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo");
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(in, out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--preReadAttributes", "*,+",
              "--postReadAttributes", "*,+"),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Provides test coverage for the --proxyV1As argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProxiedAuthorizationV1()
         throws Exception
  {
    // The in-memory directory server supports the proxied authorization v1
    // control.
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Create an LDIF file with the change to process.
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");


    // Verify that the operation fails if we try to proxy as a user that
    // doesn't exist.
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--proxyV1As", "uid=nonexistent,ou=People,dc=example,dc=com"),
         ResultCode.AUTHORIZATION_DENIED,
         new String(out.toByteArray(), "UTF-8"));


    // Verify that the operation succeeds if we try to proxy as a user that
    // does exist.
    out.reset();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--proxyV1As", "uid=test.user,ou=People,dc=example,dc=com"),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Provides test coverage for the --proxyV1As argument when using a
   * transaction.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProxiedAuthorizationV1WithTransaction()
         throws Exception
  {
    // The in-memory directory server supports the proxied authorization v1
    // control but not in transactions.  Nevertheless, we can still get
    // coverage.
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Create an LDIF file with the change to process.
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");


    // Verify that the operation succeeds.
    LDAPModify.main(getInputStream(), null, null,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--ldifFile", ldifFile.getAbsolutePath(),
         "--proxyV1As", "uid=test.user,ou=People,dc=example,dc=com",
         "--useTransaction");
  }



  /**
   * Provides test coverage for the --proxyV1As argument when using a
   * multi-update operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProxiedAuthorizationV1WithMultiUpdate()
         throws Exception
  {
    // The in-memory directory server doesn't support multi-update operations
    // but we can still get coverage.
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Create an LDIF file with the change to process.
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");


    // Verify that the operation succeeds.
    LDAPModify.main(getInputStream(), null, null,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--ldifFile", ldifFile.getAbsolutePath(),
         "--proxyV1As", "uid=test.user,ou=People,dc=example,dc=com",
         "--multiUpdateErrorBehavior", "atomic");
  }



  /**
   * Provides test coverage for the --proxyAs argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProxiedAuthorizationV2()
         throws Exception
  {
    // The in-memory directory server supports the proxied authorization v2
    // control.
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Create an LDIF file with the change to process.
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");


    // Verify that the operation fails if we try to proxy as a user that
    // doesn't exist.
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--proxyAs", "dn:uid=nonexistent,ou=People,dc=example,dc=com"),
         ResultCode.AUTHORIZATION_DENIED,
         new String(out.toByteArray(), "UTF-8"));


    // Verify that the operation succeeds if we try to proxy as a user that
    // does exist.
    out.reset();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--proxyAs", "dn:uid=test.user,ou=People,dc=example,dc=com"),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Provides test coverage for the --proxyAs argument when using a
   * transaction.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProxiedAuthorizationV2WithTransaction()
         throws Exception
  {
    // The in-memory directory server supports the proxied authorization v2
    // control but not in transactions.  Nevertheless, we can still get
    // coverage.
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Create an LDIF file with the change to process.
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");


    // Verify that the operation succeeds.
    LDAPModify.main(getInputStream(), null, null,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--ldifFile", ldifFile.getAbsolutePath(),
         "--proxyAs", "dn:uid=test.user,ou=People,dc=example,dc=com",
         "--useTransaction");
  }



  /**
   * Provides test coverage for the --proxyAs argument when using a
   * multi-update operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProxiedAuthorizationV2WithMultiUpdate()
         throws Exception
  {
    // The in-memory directory server doesn't support multi-update operations
    // but we can still get coverage.
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Create an LDIF file with the change to process.
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");


    // Verify that the operation succeeds.
    LDAPModify.main(getInputStream(), null, null,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--ldifFile", ldifFile.getAbsolutePath(),
         "--proxyAs", "dn:uid=test.user,ou=People,dc=example,dc=com",
         "--multiUpdateErrorBehavior", "atomic");
  }



  /**
   * Provides test coverage for the --clientSideSubtreeDelete argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testClientSideSubtreeDelete()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Create an LDIF file with the change to process.
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: delete");


    // Verify that the attempt to delete the dc=example,dc=com entry without
    // the subtree delete control will fail because the entry has subordinates.
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--ldifFile", ldifFile.getAbsolutePath()),
         ResultCode.NOT_ALLOWED_ON_NONLEAF,
         new String(out.toByteArray(), "UTF-8"));


    // Verify that the attempt to delete the dc=example,dc=com entry will
    // succeed when we include the subtree delete request control.
    out.reset();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--clientSideSubtreeDelete"),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Provides test coverage for the --clientSideSubtreeDelete argument when an
   * error is expected while attempting to search for entries to delete.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testClientSideSubtreeDeleteWithSearchError()
         throws Exception
  {
    // Create an in-memory directory server instance that requires
    // authentication for search operations.
    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.setAuthenticationRequiredOperationTypes(OperationType.SEARCH);
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.addEntries(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
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
    ds.startListening();

    // Create an LDIF file with the change to process.
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: delete");

    // Verify that the ldapmodify attempt fails without authentication.
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--clientSideSubtreeDelete",
              "--ldifFile", ldifFile.getAbsolutePath()),
         ResultCode.INSUFFICIENT_ACCESS_RIGHTS,
         new String(out.toByteArray(), "UTF-8"));

    // Verify that the ldapmodify attempt succeeds with authentication.
    out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--clientSideSubtreeDelete",
              "--ldifFile", ldifFile.getAbsolutePath()),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));

    // Verify that a repeated attempt fails because the base entry does not
    // exist.
    out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--clientSideSubtreeDelete",
              "--ldifFile", ldifFile.getAbsolutePath()),
         ResultCode.NO_SUCH_OBJECT,
         new String(out.toByteArray(), "UTF-8"));

    ds.shutDown(true);
  }



  /**
   * Provides test coverage for the --clientSideSubtreeDelete argument when an
   * error is expected while attempting to delete entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testClientSideSubtreeDeleteWithDeleteError()
         throws Exception
  {
    // Create an in-memory directory server instance that requires
    // authentication for search operations.
    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.setAuthenticationRequiredOperationTypes(OperationType.DELETE);
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.addEntries(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
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
    ds.startListening();

    // Create an LDIF file with the change to process.
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: delete");

    // Verify that the ldapmodify attempt fails without authentication.
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--clientSideSubtreeDelete",
              "--ldifFile", ldifFile.getAbsolutePath()),
         ResultCode.INSUFFICIENT_ACCESS_RIGHTS,
         new String(out.toByteArray(), "UTF-8"));

    // Verify that the ldapmodify attempt succeeds with authentication.
    out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--clientSideSubtreeDelete",
              "--ldifFile", ldifFile.getAbsolutePath()),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));

    ds.shutDown(true);
  }



  /**
   * Provides test coverage for the --serverSideSubtreeDelete argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testServerSideSubtreeDelete()
         throws Exception
  {
    // The in-memory directory server supports the subtree delete control.
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    // Create an LDIF file with the change to process.
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: delete");


    // Verify that the attempt to delete the dc=example,dc=com entry without
    // the subtree delete control will fail because the entry has subordinates.
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--ldifFile", ldifFile.getAbsolutePath()),
         ResultCode.NOT_ALLOWED_ON_NONLEAF,
         new String(out.toByteArray(), "UTF-8"));


    // Verify that the attempt to delete the dc=example,dc=com entry will
    // succeed when we include the subtree delete request control.
    out.reset();
    assertEquals(
         LDAPModify.main(getInputStream(), out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--serverSideSubtreeDelete"),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Provides test coverage for the uniqueness control arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUniquenessControl()
         throws Exception
  {
    // The in-memory directory server doesn't have support for the uniqueness
    // request control, but we can still use it to get coverage.
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // The lines that we'll use as test input.
    final String[] inputLDIF =
    {
      "dn: uid=test.user,ou=People,dc=example,dc=com",
      "changetype: add",
      "objectClass: top",
      "objectClass: person",
      "objectClass: organizationalPerson",
      "objectClass: inetOrgPerson",
      "uid: test.user",
      "givenName: Test",
      "sn: User",
      "cn: Test User"
    };

    // Test with a single uniqueness attribute type.
    LDAPModify.main(getInputStream(inputLDIF), null, null,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--uniquenessAttribute", "uid");

    // Test with just a uniqueness filter.
    LDAPModify.main(getInputStream(inputLDIF), null, null,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--uniquenessFilter", "(uid=test.user)");

    // Test with values for all arguments.
    LDAPModify.main(getInputStream(inputLDIF), null, null,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--uniquenessAttribute", "givenName",
         "--uniquenessAttribute", "sn",
         "--uniquenessBaseDN", "ou=People,dc=example,dc=com",
         "--uniquenessFilter", "(objectClass=person)",
         "--uniquenessMultipleAttributeBehavior",
              "unique-within-each-attribute",
         "--uniquenessPreCommitValidationLevel", "none",
         "--uniquenessPostCommitValidationLevel",
              "all-available-backend-servers");

    // Test with alternate values for the multiple attribute behavior and
    // validation level.
    LDAPModify.main(getInputStream(inputLDIF), null, null,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--uniquenessAttribute", "givenName",
         "--uniquenessAttribute", "sn",
         "--uniquenessBaseDN", "ou=People,dc=example,dc=com",
         "--uniquenessFilter", "(objectClass=person)",
         "--uniquenessMultipleAttributeBehavior",
              "unique-across-all-attributes-including-in-same-entry",
         "--uniquenessPreCommitValidationLevel", "all-subtree-views",
         "--uniquenessPostCommitValidationLevel", "all-backend-sets");

    // Test with still alternate values for the multiple attribute behavior and
    // validation level.
    LDAPModify.main(getInputStream(inputLDIF), null, null,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--uniquenessAttribute", "givenName",
         "--uniquenessAttribute", "sn",
         "--uniquenessBaseDN", "ou=People,dc=example,dc=com",
         "--uniquenessFilter", "(objectClass=person)",
         "--uniquenessMultipleAttributeBehavior",
              "unique-across-all-attributes-except-in-same-entry",
         "--uniquenessPreCommitValidationLevel", "all-backend-sets",
         "--uniquenessPostCommitValidationLevel", "all-subtree-views");

    // Test with the final alternate value for the multiple attribute behavior.
    LDAPModify.main(getInputStream(inputLDIF), null, null,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--uniquenessAttribute", "givenName",
         "--uniquenessAttribute", "sn",
         "--uniquenessBaseDN", "ou=People,dc=example,dc=com",
         "--uniquenessFilter", "(objectClass=person)",
         "--uniquenessMultipleAttributeBehavior", "unique-in-combination",
         "--uniquenessPreCommitValidationLevel",
              "all-available-backend-servers",
         "--uniquenessPostCommitValidationLevel", "none");
  }



  /**
   * Provides test coverage for a number of bind request controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindControls()
         throws Exception
  {
    // The in-memory directory server does not support many of these controls,
    // but we can at least get coverage.
    final InMemoryDirectoryServer ds = getTestDS(true, false);


    final ByteArrayInputStream in = getInputStream(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");
    LDAPModify.main(in, null, null,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--bindControl", "1.2.3.4",
         "--authorizationIdentity",
         "--getAuthorizationEntryAttribute", "*",
         "--getAuthorizationEntryAttribute", "+",
         "--getRecentLoginHistory",
         "--getUserResourceLimits",
         "--usePasswordPolicyControl",
         "--suppressOperationalAttributeUpdates", "last-access-time",
         "--suppressOperationalAttributeUpdates", "last-login-time",
         "--suppressOperationalAttributeUpdates", "last-login-ip");
  }



  /**
   * Provides test coverage for a number of add request controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddControls()
         throws Exception
  {
    // The in-memory directory server does not support many of these controls,
    // but we can at least get coverage.
    final InMemoryDirectoryServer ds = getTestDS(true, false);


    final ByteArrayInputStream in = getInputStream(
         "dn: ou=test,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test",
         "userPassword: password",
         "ds-undelete-from-dn: ou=foo,dc=example,dc=com");
    LDAPModify.main(in, null, null,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--control", "1.2.3.4",
         "--addControl", "1.2.3.5",
         "--generatePassword",
         "--ignoreNoUserModification",
         "--nameWithEntryUUID",
         "--suppressOperationalAttributeUpdates", "last-access-time",
         "--suppressOperationalAttributeUpdates", "last-login-time",
         "--suppressOperationalAttributeUpdates", "last-login-ip",
         "--suppressOperationalAttributeUpdates", "lastmod",
         "--usePasswordPolicyControl",
         "--useAssuredReplication",
         "--assuredReplicationLocalLevel", "none",
         "--assuredReplicationRemoteLevel", "none",
         "--assuredReplicationTimeout", "30s",
         "--replicationRepair",
         "--operationPurpose", "testAddControls",
         "--getPasswordValidationDetails",
         "--allowUndelete");
  }



  /**
   * Provides test coverage for a number of delete request controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteControls()
         throws Exception
  {
    // The in-memory directory server does not support many of these controls,
    // but we can at least get coverage.
    final InMemoryDirectoryServer ds = getTestDS(true, false);


    final ByteArrayInputStream in = getInputStream(
         "dn: dc=example,dc=com",
         "changetype: delete");
    LDAPModify.main(in, null, null,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--control", "1.2.3.4",
         "--deleteControl", "1.2.3.5",
         "--suppressReferentialIntegrityUpdates",
         "--suppressOperationalAttributeUpdates", "last-access-time",
         "--suppressOperationalAttributeUpdates", "last-login-time",
         "--suppressOperationalAttributeUpdates", "last-login-ip",
         "--suppressOperationalAttributeUpdates", "lastmod",
         "--useAssuredReplication",
         "--assuredReplicationLocalLevel", "received-any-server",
         "--assuredReplicationRemoteLevel", "received-any-remote-location",
         "--assuredReplicationTimeout", "30s",
         "--replicationRepair",
         "--hardDelete",
         "--serverSideSubtreeDelete",
         "--operationPurpose", "testAddControls");
  }



  /**
   * Provides test coverage for a number of modify request controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyControls()
         throws Exception
  {
    // The in-memory directory server does not support many of these controls,
    // but we can at least get coverage.
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    ByteArrayInputStream in = getInputStream(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: userPassword",
         "userPassword: newPassword");
    LDAPModify.main(in, null, null,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--control", "1.2.3.4",
         "--modifyControl", "1.2.3.5",
         "--suppressOperationalAttributeUpdates", "last-access-time",
         "--suppressOperationalAttributeUpdates", "last-login-time",
         "--suppressOperationalAttributeUpdates", "last-login-ip",
         "--suppressOperationalAttributeUpdates", "lastmod",
         "--useAssuredReplication",
         "--assuredReplicationLocalLevel", "processed-all-servers",
         "--assuredReplicationRemoteLevel", "received-all-remote-locations",
         "--assuredReplicationTimeout", "30s",
         "--replicationRepair",
         "--softDelete",
         "--operationPurpose", "testAddControls",
         "--retireCurrentPassword",
         "--getPasswordValidationDetails");


    in = getInputStream(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: authPassword",
         "authPassword: newPassword");
    LDAPModify.main(in, null, null,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--purgeCurrentPassword");
  }



  /**
   * Provides test coverage for a number of modify DN request controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNControls()
         throws Exception
  {
    // The in-memory directory server does not support many of these controls,
    // but we can at least get coverage.
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    final ByteArrayInputStream in = getInputStream(
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: 1");
    LDAPModify.main(in, null, null,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--control", "1.2.3.4",
         "--modifyDNControl", "1.2.3.5",
         "--suppressReferentialIntegrityUpdates",
         "--suppressOperationalAttributeUpdates", "last-access-time",
         "--suppressOperationalAttributeUpdates", "last-login-time",
         "--suppressOperationalAttributeUpdates", "last-login-ip",
         "--suppressOperationalAttributeUpdates", "lastmod",
         "--useAssuredReplication",
         "--assuredReplicationLocalLevel", "processed-all-servers",
         "--assuredReplicationRemoteLevel", "processed-all-remote-servers",
         "--assuredReplicationTimeout", "30s",
         "--replicationRepair",
         "--operationPurpose", "testAddControls");
  }



  /**
   * Provides test coverage for the --modifyEntriesMatchingFilter argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyEntriesMatchingFilter()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ds.add(
         "dn: uid=another.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: another.user",
         "givenName: Another",
         "sn: User",
         "cn: Another User");


    // Get a file to use as an output file.
    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());


    // Update the description for all users matching (objectClass=person).
    final ByteArrayInputStream in = getInputStream(
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo");
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(in, out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--modifyEntriesMatchingFilter", "(objectClass=person)",
              "--verbose",
              "--outputFile", outputFile.getAbsolutePath(),
              "--ratePerSecond", "10000"),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));


    // Ensure that both test.user and another.user have description values of
    // foo.
    ds.assertValueExists("uid=test.user,ou=People,dc=example,dc=com",
         "description", "foo");
    ds.assertValueExists("uid=another.user,ou=People,dc=example,dc=com",
         "description", "foo");


    // Ensure that the output file exists and is not empty.
    assertTrue(outputFile.exists());
    assertTrue(outputFile.length() > 0L);
  }



  /**
   * Provides test coverage for the --modifyEntriesMatchingFilter argument when
   * the attempted change is not a modify operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyEntriesMatchingFilterNotModification()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Get a file to use as an output file.
    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());


    // Update the description for all users matching (objectClass=person).
    final ByteArrayInputStream in = getInputStream(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changeType: delete");
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(in, out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--modifyEntriesMatchingFilter", "(objectClass=person)",
              "--verbose",
              "--outputFile", outputFile.getAbsolutePath(),
              "--ratePerSecond", "10000"),
         ResultCode.PARAM_ERROR,
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Provides test coverage for the --modifyEntriesMatchingFilter argument
   * without any matching entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyEntriesMatchingFilterNoMatches()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Update the description for all users matching (description=noMatch).
    final ByteArrayInputStream in = getInputStream(
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo");
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(in, out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--modifyEntriesMatchingFilter", "(description=noMatch)"),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Provides test coverage for the --modifyEntriesMatchingFilter argument with
   * a change that will be rejected.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyEntriesMatchingFilterFailedModification()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Update the description for all users matching (description=noMatch).
    final ByteArrayInputStream in = getInputStream(
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: undefinedAttribute",
         "undefinedAttribute: foo");
    final ByteArrayOutputStream out = new ByteArrayOutputStream();

     final ResultCode resultCode = LDAPModify.main(in, out, out,
          "--hostname", "localhost",
          "--port", String.valueOf(ds.getListenPort()),
          "--bindDN", "cn=Directory Manager",
          "--bindPassword", "password",
          "--modifyEntriesMatchingFilter", "(objectClass=person)");
    assertFalse((resultCode == ResultCode.SUCCESS),
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Provides test coverage for the --modifyEntriesMatchingFiltersFromFile
   * argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyEntriesMatchingFilterFromFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    for (int i=0; i < 10; i++)
    {
      ds.add(
           "dn: uid=user." + i + ",ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: user." + i,
           "givenName: User",
           "sn: " + i,
           "cn: User " + i,
           "description: unchanged");
    }


    // Create a couple of filter files with multiple filters each.
    final File filterFile1 = createTempFile(
         "(uid=user.0)",
         "(uid=user.1)",
         "(uid=user.2)");

    final File filterFile2 = createTempFile(
         "(uid=user.5)",
         "(uid=user.6)",
         "invalid",
         "(uid=user.7)");


    // Get a file to use as an output file.
    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());


    // Update the description for all users matching (objectClass=person).
    final ByteArrayInputStream in = getInputStream(
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo");
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(in, out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--modifyEntriesMatchingFiltersFromFile",
                   filterFile1.getAbsolutePath(),
              "--modifyEntriesMatchingFiltersFromFile",
                   filterFile2.getAbsolutePath(),
              "--verbose",
              "--outputFile", outputFile.getAbsolutePath(),
              "--ratePerSecond", "10000",
              "--continueOnError"),
         ResultCode.FILTER_ERROR,
         new String(out.toByteArray(), "UTF-8"));


    // Ensure that all of the users have the expected values.
    ds.assertValueExists("uid=user.0,ou=People,dc=example,dc=com",
         "description", "foo");
    ds.assertValueExists("uid=user.1,ou=People,dc=example,dc=com",
         "description", "foo");
    ds.assertValueExists("uid=user.2,ou=People,dc=example,dc=com",
         "description", "foo");
    ds.assertValueExists("uid=user.3,ou=People,dc=example,dc=com",
         "description", "unchanged");
    ds.assertValueExists("uid=user.4,ou=People,dc=example,dc=com",
         "description", "unchanged");
    ds.assertValueExists("uid=user.5,ou=People,dc=example,dc=com",
         "description", "foo");
    ds.assertValueExists("uid=user.6,ou=People,dc=example,dc=com",
         "description", "foo");
    ds.assertValueExists("uid=user.7,ou=People,dc=example,dc=com",
         "description", "foo");
    ds.assertValueExists("uid=user.8,ou=People,dc=example,dc=com",
         "description", "unchanged");
    ds.assertValueExists("uid=user.9,ou=People,dc=example,dc=com",
         "description", "unchanged");


    // Ensure that the output file exists and is not empty.
    assertTrue(outputFile.exists());
    assertTrue(outputFile.length() > 0L);
  }



  /**
   * Provides test coverage for the --modifyEntryWithDN argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyEntryWithDN()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ds.add(
         "dn: uid=another.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: another.user",
         "givenName: Another",
         "sn: User",
         "cn: Another User");


    // Get a file to use as an output file.
    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());


    // Update the description for all users matching (objectClass=person).
    final ByteArrayInputStream in = getInputStream(
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo");
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(in, out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--modifyEntryWithDN",
                   "uid=test.user,ou=People,dc=example,dc=com",
              "--modifyEntryWithDN",
                   "uid=another.user,ou=People,dc=example,dc=com",
              "--verbose",
              "--outputFile", outputFile.getAbsolutePath(),
              "--ratePerSecond", "10000"),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));


    // Ensure that both test.user and another.user have description values of
    // foo.
    ds.assertValueExists("uid=test.user,ou=People,dc=example,dc=com",
         "description", "foo");
    ds.assertValueExists("uid=another.user,ou=People,dc=example,dc=com",
         "description", "foo");


    // Ensure that the output file exists and is not empty.
    assertTrue(outputFile.exists());
    assertTrue(outputFile.length() > 0L);
  }



  /**
   * Provides test coverage for the --modifyEntryWithDN argument with a change
   * that is not a modification.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyEntryWithDNNotModification()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Get a file to use as an output file.
    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());


    // Update the description for all users matching (objectClass=person).
    final ByteArrayInputStream in = getInputStream(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changeType: delete");
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(in, out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--modifyEntryWithDN",
                   "uid=another.user,ou=People,dc=example,dc=com",
              "--verbose",
              "--outputFile", outputFile.getAbsolutePath(),
              "--ratePerSecond", "10000",
              "--continueOnError"),
         ResultCode.PARAM_ERROR,
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Provides test coverage for the --modifyEntryWithDN argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyEntryWithDNNoSuchEntry()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Get a file to use as an output file.
    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());


    // Update the description for all users matching (objectClass=person).
    final ByteArrayInputStream in = getInputStream(
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo");
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(in, out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--modifyEntryWithDN",
                   "uid=another.user,ou=People,dc=example,dc=com",
              "--verbose",
              "--outputFile", outputFile.getAbsolutePath(),
              "--ratePerSecond", "10000"),
         ResultCode.NO_SUCH_OBJECT,
         new String(out.toByteArray(), "UTF-8"));


    // Ensure that the output file exists and is not empty.
    assertTrue(outputFile.exists());
    assertTrue(outputFile.length() > 0L);
  }



  /**
   * Provides test coverage for the --modifyEntriesWithDNsFromFile
   * argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyEntriesWithDNsFromFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    for (int i=0; i < 10; i++)
    {
      ds.add(
           "dn: uid=user." + i + ",ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: user." + i,
           "givenName: User",
           "sn: " + i,
           "cn: User " + i,
           "description: unchanged");
    }


    // Create a couple of filter files with multiple filters each.
    final File dnFile1 = createTempFile(
         "uid=user.0,ou=People,dc=example,dc=com",
         "invalid 1",
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "dn: invalid 2",
         "dn:: " + Base64.encode("uid=user.2,ou=People,dc=example,dc=com"),
         "dn:: invalid 3");

    final File dnFile2 = createTempFile(
         "uid=user.5,ou=People,dc=example,dc=com",
         "dn:invalid 4",
         "dn: uid=user.6,ou=People,dc=example,dc=com",
         "dn::invalid 5",
         "dn:: " + Base64.encode("uid=user.7,ou=People,dc=example,dc=com"));


    // Get a file to use as an output file.
    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());


    // Update the description for all users matching (objectClass=person).
    final ByteArrayInputStream in = getInputStream(
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo");
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(in, out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--modifyEntriesWithDNsFromFile", dnFile1.getAbsolutePath(),
              "--modifyEntriesWithDNsFromFile", dnFile2.getAbsolutePath(),
              "--verbose",
              "--outputFile", outputFile.getAbsolutePath(),
              "--ratePerSecond", "10000",
              "--continueOnError"),
         ResultCode.INVALID_DN_SYNTAX,
         new String(out.toByteArray(), "UTF-8"));


    // Ensure that all of the users have the expected values.
    ds.assertValueExists("uid=user.0,ou=People,dc=example,dc=com",
         "description", "foo");
    ds.assertValueExists("uid=user.1,ou=People,dc=example,dc=com",
         "description", "foo");
    ds.assertValueExists("uid=user.2,ou=People,dc=example,dc=com",
         "description", "foo");
    ds.assertValueExists("uid=user.3,ou=People,dc=example,dc=com",
         "description", "unchanged");
    ds.assertValueExists("uid=user.4,ou=People,dc=example,dc=com",
         "description", "unchanged");
    ds.assertValueExists("uid=user.5,ou=People,dc=example,dc=com",
         "description", "foo");
    ds.assertValueExists("uid=user.6,ou=People,dc=example,dc=com",
         "description", "foo");
    ds.assertValueExists("uid=user.7,ou=People,dc=example,dc=com",
         "description", "foo");
    ds.assertValueExists("uid=user.8,ou=People,dc=example,dc=com",
         "description", "unchanged");
    ds.assertValueExists("uid=user.9,ou=People,dc=example,dc=com",
         "description", "unchanged");


    // Ensure that the output file exists and is not empty.
    assertTrue(outputFile.exists());
    assertTrue(outputFile.length() > 0L);
  }



  /**
   * Tests the ability to process compressed and encrypted LDIF data when the
   * encryption passphrase is provided in a file that isn't a valid passphrase
   * file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompressedAndEncryptedInputWithPassphraseFromMalformedFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(false, false);

    final File inputFile = createTempFile();
    assertTrue(inputFile.delete());

    final PrintStream printStream = new PrintStream(new GZIPOutputStream(
         new PassphraseEncryptedOutputStream("passphrase", new FileOutputStream(
              inputFile))));
    printStream.println("dn: dc=example,dc=com");
    printStream.println("changetype: add");
    printStream.println("objectClass: top");
    printStream.println("objectClass: domain");
    printStream.println("dc: example");
    printStream.close();

    final File passphraseFile = createTempFile(); // Shouldn't be empty.

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(null, out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--ldifFile", inputFile.getAbsolutePath(),
              "--encryptionPassphraseFile", passphraseFile.getAbsolutePath()),
         ResultCode.PARAM_ERROR,
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Tests the ability to process compressed and encrypted LDIF data when the
   * encryption passphrase is provided in a file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompressedAndEncryptedInputWithPassphraseFromFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(false, false);

    final File inputFile = createTempFile();
    assertTrue(inputFile.delete());

    final PrintStream printStream = new PrintStream(new GZIPOutputStream(
         new PassphraseEncryptedOutputStream("passphrase", new FileOutputStream(
              inputFile))));
    printStream.println("dn: dc=example,dc=com");
    printStream.println("changetype: add");
    printStream.println("objectClass: top");
    printStream.println("objectClass: domain");
    printStream.println("dc: example");
    printStream.close();

    final File passphraseFile = createTempFile("passphrase");

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPModify.main(null, out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "password",
              "--ldifFile", inputFile.getAbsolutePath(),
              "--encryptionPassphraseFile", passphraseFile.getAbsolutePath()),
         ResultCode.SUCCESS,
         new String(out.toByteArray(), "UTF-8"));
  }



  /**
   * Tests the ability to process compressed and encrypted LDIF data when the
   * encryption passphrase is provided at an interactive prompt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompressedAndEncryptedInputWithPassphraseFromPrompt()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(false, false);

    final File inputFile = createTempFile();
    assertTrue(inputFile.delete());

    final PrintStream printStream = new PrintStream(new GZIPOutputStream(
         new PassphraseEncryptedOutputStream("passphrase", new FileOutputStream(
              inputFile))));
    printStream.println("dn: dc=example,dc=com");
    printStream.println("changetype: add");
    printStream.println("objectClass: top");
    printStream.println("objectClass: domain");
    printStream.println("dc: example");
    printStream.close();

    try
    {
      PasswordReader.setTestReaderLines("passphrase");

      final ByteArrayOutputStream out = new ByteArrayOutputStream();
      assertEquals(
           LDAPModify.main(null, out, out,
                "--hostname", "localhost",
                "--port", String.valueOf(ds.getListenPort()),
                "--bindDN", "cn=Directory Manager",
                "--bindPassword", "password",
                "--ldifFile", inputFile.getAbsolutePath()),
           ResultCode.SUCCESS,
           new String(out.toByteArray(), "UTF-8"));
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Retrieves an input stream that may be used to read the provided lines.
   *
   * @param  lines  The lines to make available in the input stream.
   *
   * @return  An input stream that may be used to read the provided lines.
   */
  private static ByteArrayInputStream getInputStream(final String... lines)
  {
    if (lines.length == 0)
    {
      return new ByteArrayInputStream(StaticUtils.NO_BYTES);
    }

    final ByteStringBuffer buffer = new ByteStringBuffer();
    for (final String line : lines)
    {
      buffer.append(line);
      buffer.append(StaticUtils.EOL_BYTES);
    }

    return new ByteArrayInputStream(buffer.toByteArray());
  }



  /**
   * Provides test coverage for the behavior exhibited when a malformed control
   * value (and in particular, a malformed password update behavior control
   * specification) is given.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedControl()
         throws Exception
  {
    // The in-memory directory server supports the read entry controls.
    final InMemoryDirectoryServer ds = getTestDS(true, false);


    final ByteArrayInputStream in = getInputStream(
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo");
    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode resultCode = LDAPModify.main(in, out, out,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--passwordUpdateBehavior", "this-is-not-valid");
    assertFalse(resultCode == ResultCode.SUCCESS);
  }



  /**
   * Provides test coverage for the ability to request the password update
   * behavior request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordUpdateBehavior()
         throws Exception
  {
    for (final String value :
         Arrays.asList("is-self-change",
              "self-change",
              "isSelfChange",
              "selfChange"))
    {
      final String trueValueEquals = value + "=true";
      PasswordUpdateBehaviorRequestControl c =
           LDAPModify.createPasswordUpdateBehaviorRequestControl(
                "--passwordUpdateBehavior",
                Collections.singletonList(trueValueEquals));
      assertNotNull(c);

      assertNotNull(c.getIsSelfChange());
      assertEquals(c.getIsSelfChange(), Boolean.TRUE);

      assertNull(c.getAllowPreEncodedPassword());
      assertNull(c.getSkipPasswordValidation());
      assertNull(c.getIgnorePasswordHistory());
      assertNull(c.getIgnoreMinimumPasswordAge());
      assertNull(c.getPasswordStorageScheme());
      assertNull(c.getMustChangePassword());

      final String trueValueColon = "  " + value + " : true ";
      c = LDAPModify.createPasswordUpdateBehaviorRequestControl(
           "--passwordUpdateBehavior",
           Collections.singletonList(trueValueColon));
      assertNotNull(c);

      assertNotNull(c.getIsSelfChange());
      assertEquals(c.getIsSelfChange(), Boolean.TRUE);

      assertNull(c.getAllowPreEncodedPassword());
      assertNull(c.getSkipPasswordValidation());
      assertNull(c.getIgnorePasswordHistory());
      assertNull(c.getIgnoreMinimumPasswordAge());
      assertNull(c.getPasswordStorageScheme());
      assertNull(c.getMustChangePassword());

      final String falseValueColon = value + ":false";
      c = LDAPModify.createPasswordUpdateBehaviorRequestControl(
           "--passwordUpdateBehavior",
           Collections.singletonList(falseValueColon));
      assertNotNull(c);

      assertNotNull(c.getIsSelfChange());
      assertEquals(c.getIsSelfChange(), Boolean.FALSE);

      assertNull(c.getAllowPreEncodedPassword());
      assertNull(c.getSkipPasswordValidation());
      assertNull(c.getIgnorePasswordHistory());
      assertNull(c.getIgnoreMinimumPasswordAge());
      assertNull(c.getPasswordStorageScheme());
      assertNull(c.getMustChangePassword());
    }


    for (final String value :
         Arrays.asList("allow-pre-encoded-password",
              "allow-pre-encoded-passwords",
              "allow-pre-encoded",
              "allowPreEncodedPassword",
              "allowPreEncodedPasswords",
              "allowPreEncoded"))
    {
      final String trueValue = value + "=t";
      PasswordUpdateBehaviorRequestControl c =
           LDAPModify.createPasswordUpdateBehaviorRequestControl(
                "--passwordUpdateBehavior",
                Collections.singletonList(trueValue));
      assertNotNull(c);

      assertNull(c.getIsSelfChange());

      assertNotNull(c.getAllowPreEncodedPassword());
      assertEquals(c.getAllowPreEncodedPassword(), Boolean.TRUE);

      assertNull(c.getSkipPasswordValidation());
      assertNull(c.getIgnorePasswordHistory());
      assertNull(c.getIgnoreMinimumPasswordAge());
      assertNull(c.getPasswordStorageScheme());
      assertNull(c.getMustChangePassword());

      final String falseValue = value + "=f";
      c = LDAPModify.createPasswordUpdateBehaviorRequestControl(
           "--passwordUpdateBehavior",
           Collections.singletonList(falseValue));
      assertNotNull(c);

      assertNull(c.getIsSelfChange());

      assertNotNull(c.getAllowPreEncodedPassword());
      assertEquals(c.getAllowPreEncodedPassword(), Boolean.FALSE);

      assertNull(c.getSkipPasswordValidation());
      assertNull(c.getIgnorePasswordHistory());
      assertNull(c.getIgnoreMinimumPasswordAge());
      assertNull(c.getPasswordStorageScheme());
      assertNull(c.getMustChangePassword());
    }


    for (final String value :
         Arrays.asList("skip-password-validation",
              "skip-password-validators",
              "skip-validation",
              "skip-validators",
              "skipPasswordValidation",
              "skipPasswordValidators",
              "skipValidation",
              "skipValidators"))
    {
      final String trueValue = value + "=yes";
      PasswordUpdateBehaviorRequestControl c =
           LDAPModify.createPasswordUpdateBehaviorRequestControl(
                "--passwordUpdateBehavior",
                Collections.singletonList(trueValue));
      assertNotNull(c);

      assertNull(c.getIsSelfChange());
      assertNull(c.getAllowPreEncodedPassword());

      assertNotNull(c.getSkipPasswordValidation());
      assertEquals(c.getSkipPasswordValidation(), Boolean.TRUE);

      assertNull(c.getIgnorePasswordHistory());
      assertNull(c.getIgnoreMinimumPasswordAge());
      assertNull(c.getPasswordStorageScheme());
      assertNull(c.getMustChangePassword());

      final String falseValue = value + "=no";
      c = LDAPModify.createPasswordUpdateBehaviorRequestControl(
           "--passwordUpdateBehavior",
           Collections.singletonList(falseValue));
      assertNotNull(c);

      assertNull(c.getIsSelfChange());
      assertNull(c.getAllowPreEncodedPassword());

      assertNotNull(c.getSkipPasswordValidation());
      assertEquals(c.getSkipPasswordValidation(), Boolean.FALSE);

      assertNull(c.getIgnorePasswordHistory());
      assertNull(c.getIgnoreMinimumPasswordAge());
      assertNull(c.getPasswordStorageScheme());
      assertNull(c.getMustChangePassword());
    }


    for (final String value :
         Arrays.asList("ignore-password-history",
              "skip-password-history",
              "ignore-history",
              "skip-history",
              "ignorePasswordHistory",
              "skipPasswordHistory",
              "ignoreHistory",
              "skipHistory"))
    {
      final String trueValue = value + "=y";
      PasswordUpdateBehaviorRequestControl c =
           LDAPModify.createPasswordUpdateBehaviorRequestControl(
                "--passwordUpdateBehavior",
                Collections.singletonList(trueValue));
      assertNotNull(c);

      assertNull(c.getIsSelfChange());
      assertNull(c.getAllowPreEncodedPassword());
      assertNull(c.getSkipPasswordValidation());

      assertNotNull(c.getIgnorePasswordHistory());
      assertEquals(c.getIgnorePasswordHistory(), Boolean.TRUE);

      assertNull(c.getIgnoreMinimumPasswordAge());
      assertNull(c.getPasswordStorageScheme());
      assertNull(c.getMustChangePassword());

      final String falseValue = value + "=n";
      c = LDAPModify.createPasswordUpdateBehaviorRequestControl(
           "--passwordUpdateBehavior",
           Collections.singletonList(falseValue));
      assertNotNull(c);

      assertNull(c.getIsSelfChange());
      assertNull(c.getAllowPreEncodedPassword());
      assertNull(c.getSkipPasswordValidation());

      assertNotNull(c.getIgnorePasswordHistory());
      assertEquals(c.getIgnorePasswordHistory(), Boolean.FALSE);

      assertNull(c.getIgnoreMinimumPasswordAge());
      assertNull(c.getPasswordStorageScheme());
      assertNull(c.getMustChangePassword());
    }


    for (final String value :
         Arrays.asList("ignore-minimum-password-age",
              "ignore-min-password-age",
              "ignore-password-age",
              "skip-minimum-password-age",
              "skip-min-password-age",
              "skip-password-age",
              "ignoreMinimumPasswordAge",
              "ignoreMinPasswordAge",
              "ignorePasswordAge",
              "skipMinimumPasswordAge",
              "skipMinPasswordAge",
              "skipPasswordAge"))
    {
      final String trueValue = value + "=1";
      PasswordUpdateBehaviorRequestControl c =
           LDAPModify.createPasswordUpdateBehaviorRequestControl(
                "--passwordUpdateBehavior",
                Collections.singletonList(trueValue));
      assertNotNull(c);

      assertNull(c.getIsSelfChange());
      assertNull(c.getAllowPreEncodedPassword());
      assertNull(c.getSkipPasswordValidation());
      assertNull(c.getIgnorePasswordHistory());

      assertNotNull(c.getIgnoreMinimumPasswordAge());
      assertEquals(c.getIgnoreMinimumPasswordAge(), Boolean.TRUE);

      assertNull(c.getPasswordStorageScheme());
      assertNull(c.getMustChangePassword());

      final String falseValue = value + "=0";
      c = LDAPModify.createPasswordUpdateBehaviorRequestControl(
           "--passwordUpdateBehavior",
           Collections.singletonList(falseValue));
      assertNotNull(c);

      assertNull(c.getIsSelfChange());
      assertNull(c.getAllowPreEncodedPassword());
      assertNull(c.getSkipPasswordValidation());
      assertNull(c.getIgnorePasswordHistory());

      assertNotNull(c.getIgnoreMinimumPasswordAge());
      assertEquals(c.getIgnoreMinimumPasswordAge(), Boolean.FALSE);

      assertNull(c.getPasswordStorageScheme());
      assertNull(c.getMustChangePassword());
    }


    for (final String value :
         Arrays.asList("password-storage-scheme",
              "password-scheme",
              "storage-scheme",
              "scheme",
              "passwordStorageScheme",
              "passwordScheme",
              "storageScheme"))
    {
      final String ssha512Value = value + "=SSHA512";
      final PasswordUpdateBehaviorRequestControl c =
           LDAPModify.createPasswordUpdateBehaviorRequestControl(
                "--passwordUpdateBehavior",
                Collections.singletonList(ssha512Value));
      assertNotNull(c);

      assertNull(c.getIsSelfChange());
      assertNull(c.getAllowPreEncodedPassword());
      assertNull(c.getSkipPasswordValidation());
      assertNull(c.getIgnorePasswordHistory());
      assertNull(c.getIgnoreMinimumPasswordAge());

      assertNotNull(c.getPasswordStorageScheme());
      assertEquals(c.getPasswordStorageScheme(), "SSHA512");

      assertNull(c.getMustChangePassword());
    }


    for (final String value :
         Arrays.asList("must-change-password",
              "mustChangePassword"))
    {
      final String trueValue = value + "=true";
      PasswordUpdateBehaviorRequestControl c =
           LDAPModify.createPasswordUpdateBehaviorRequestControl(
                "--passwordUpdateBehavior",
                Collections.singletonList(trueValue));
      assertNotNull(c);

      assertNull(c.getIsSelfChange());
      assertNull(c.getAllowPreEncodedPassword());
      assertNull(c.getSkipPasswordValidation());
      assertNull(c.getIgnorePasswordHistory());
      assertNull(c.getIgnoreMinimumPasswordAge());
      assertNull(c.getPasswordStorageScheme());

      assertNotNull(c.getMustChangePassword());
      assertEquals(c.getMustChangePassword(), Boolean.TRUE);

      final String falseValue = value + "=false";
      c = LDAPModify.createPasswordUpdateBehaviorRequestControl(
           "--passwordUpdateBehavior",
           Collections.singletonList(falseValue));
      assertNotNull(c);

      assertNull(c.getIsSelfChange());
      assertNull(c.getAllowPreEncodedPassword());
      assertNull(c.getSkipPasswordValidation());
      assertNull(c.getIgnorePasswordHistory());
      assertNull(c.getIgnoreMinimumPasswordAge());
      assertNull(c.getPasswordStorageScheme());

      assertNotNull(c.getMustChangePassword());
      assertEquals(c.getMustChangePassword(), Boolean.FALSE);
    }


    try
    {
      LDAPModify.createPasswordUpdateBehaviorRequestControl(
           "--passwordUpdateBehavior",
           Collections.singletonList("malformed-value"));
      fail("Expected an exception from a malformed value");
    }
    catch (final LDAPException le)
    {
      // This was expected.
      assertResultCodeEquals(le, ResultCode.PARAM_ERROR);
    }

    try
    {
      LDAPModify.createPasswordUpdateBehaviorRequestControl(
           "--passwordUpdateBehavior",
           Collections.singletonList("equal-at-end="));
      fail("Expected an exception from value ending with an equal sign");
    }
    catch (final LDAPException le)
    {
      // This was expected.
      assertResultCodeEquals(le, ResultCode.PARAM_ERROR);
    }

    try
    {
      LDAPModify.createPasswordUpdateBehaviorRequestControl(
           "--passwordUpdateBehavior",
           Collections.singletonList("colon-at-end:"));
      fail("Expected an exception from value ending with a colon");
    }
    catch (final LDAPException le)
    {
      // This was expected.
      assertResultCodeEquals(le, ResultCode.PARAM_ERROR);
    }

    try
    {
      LDAPModify.createPasswordUpdateBehaviorRequestControl(
           "--passwordUpdateBehavior",
           Collections.singletonList("=true"));
      fail("Expected an exception from value beginning with an equal sign");
    }
    catch (final LDAPException le)
    {
      // This was expected.
      assertResultCodeEquals(le, ResultCode.PARAM_ERROR);
    }

    try
    {
      LDAPModify.createPasswordUpdateBehaviorRequestControl(
           "--passwordUpdateBehavior",
           Collections.singletonList(":false"));
      fail("Expected an exception from value beginning with a colon");
    }
    catch (final LDAPException le)
    {
      // This was expected.
      assertResultCodeEquals(le, ResultCode.PARAM_ERROR);
    }

    try
    {
      LDAPModify.createPasswordUpdateBehaviorRequestControl(
           "--passwordUpdateBehavior",
           Collections.singletonList("must-change-password=malformed"));
      fail("Expected an exception from a malformed Boolean value");
    }
    catch (final LDAPException le)
    {
      // This was expected.
      assertResultCodeEquals(le, ResultCode.PARAM_ERROR);
    }
  }



  /**
   * Provides test coverage for the controls used to get and request routing
   * information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRoutingControls()
         throws Exception
  {
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds.startListening();
    final int dsPort = ds.getListenPort();
    ds.shutDown(true);

    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    LDAPModify.main(new ByteArrayInputStream(StaticUtils.NO_BYTES), null, null,
         "--hostname", "localhost",
         "--port", String.valueOf(dsPort),
         "--getBackendSetID",
         "--getServerID",
         "--routeToBackendSet", "rp1:bs1",
         "--routeToBackendSet", "rp1:bs2",
         "--routeToBackendSet", "rp2:bs3",
         "--routeToServer", "server-id",
         "--ldifFile", ldifFile.getAbsolutePath());

    LDAPModify.main(new ByteArrayInputStream(StaticUtils.NO_BYTES), null, null,
         "--hostname", "localhost",
         "--port", String.valueOf(dsPort),
         "--routeToBackendSet", "malformed",
         "--ldifFile", ldifFile.getAbsolutePath());
  }
}
