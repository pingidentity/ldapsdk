/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import java.io.File;
import java.security.MessageDigest;
import java.util.Collections;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.PLAINBindRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedRequest;
import com.unboundid.util.Base64;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a number of test cases for the in-memory directory server
 * with password encoding enabled.
 */
public final class InMemoryDirectoryServerPasswordEncodingTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a broad set of password encoding functionality.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBroadFunctionality()
         throws Exception
  {
    // Create an in-memory directory server instance with support for a lot of
    // password encoders.
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    final MessageDigest sha1Digest = CryptoHelper.getMessageDigest("SHA-1");
    config.setPasswordEncoders(
         new ClearInMemoryPasswordEncoder("{CLEAR}", null),
         new ClearInMemoryPasswordEncoder("{HEX}",
              HexPasswordEncoderOutputFormatter.getLowercaseInstance()),
         new ClearInMemoryPasswordEncoder("{BASE64}",
              Base64PasswordEncoderOutputFormatter.getInstance()),
         new UnsaltedMessageDigestInMemoryPasswordEncoder("{SHA}",
              Base64PasswordEncoderOutputFormatter.getInstance(), sha1Digest));

    assertNotNull(config.getPasswordAttributes());
    assertFalse(config.getPasswordAttributes().isEmpty());
    assertEquals(config.getPasswordAttributes(),
         Collections.singleton("userPassword"));

    assertNotNull(config.getPrimaryPasswordEncoder());

    assertNotNull(config.getSecondaryPasswordEncoders());
    assertFalse(config.getSecondaryPasswordEncoders().isEmpty());

    assertNotNull(config.toString());

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
    ds.startListening();


    // Import LDIF data into the in-memory directory server.  It will include a
    // mix of clear-text and encoded passwords.
    final byte[] passwordBytes = StaticUtils.getBytes("password");
    final String clearPassword = "{CLEAR}password";
    final String hexPassword = "{HEX}" + StaticUtils.toHex(passwordBytes);
    final String base64Password = "{BASE64}" + Base64.encode(passwordBytes);
    final String shaPassword =
         "{SHA}" + Base64.encode(sha1Digest.digest(passwordBytes));
    final File ldifFile = createTempFile(
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
         "dn: uid=imported.unencoded,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: imported.unencoded",
         "givenName: Imported",
         "sn: Unencoded",
         "cn: Imported Unencoded",
         "userPassword: password",
         "",
         "dn: uid=imported.clear,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: imported.clear",
         "givenName: Imported",
         "sn: Clear",
         "cn: Imported Clear",
         "userPassword: " + clearPassword,
         "",
         "dn: uid=imported.hex,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: imported.hex",
         "givenName: Imported",
         "sn: Hex",
         "cn: Imported Hex",
         "userPassword: " + hexPassword,
         "",
         "dn: uid=imported.base64,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: imported.base64",
         "givenName: Imported",
         "sn: Base64",
         "cn: Imported Base64",
         "userPassword: " + base64Password,
         "",
         "dn: uid=imported.sha,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: imported.sha",
         "givenName: Imported",
         "sn: SHA",
         "cn: Imported SHA",
         "userPassword: " + shaPassword);
    ds.importFromLDIF(true, ldifFile.getAbsolutePath());


    // Verify that the passwords in the import were handled properly.  The
    // unencoded password should have been encoded.  The encoded passwords
    // should have been left intact.
    assertEquals(
         ds.getEntry("uid=imported.unencoded,ou=People,dc=example,dc=com",
              "userPassword").getAttributeValue("userPassword"),
         "{CLEAR}password");
    assertEquals(
         ds.getEntry("uid=imported.clear,ou=People,dc=example,dc=com",
              "userPassword").getAttributeValue("userPassword"),
         clearPassword);
    assertEquals(
         ds.getEntry("uid=imported.hex,ou=People,dc=example,dc=com",
              "userPassword").getAttributeValue("userPassword"),
         hexPassword);
    assertEquals(
         ds.getEntry("uid=imported.base64,ou=People,dc=example,dc=com",
              "userPassword").getAttributeValue("userPassword"),
         base64Password);
    assertEquals(
         ds.getEntry("uid=imported.sha,ou=People,dc=example,dc=com",
              "userPassword").getAttributeValue("userPassword"),
         shaPassword);


    // Test methods for interacting with passwords.
    assertNotNull(ds.getPasswordAttributes());
    assertEquals(ds.getPasswordAttributes(),
         Collections.singletonList("userPassword"));

    assertNotNull(ds.getPrimaryPasswordEncoder());
    assertEquals(ds.getPrimaryPasswordEncoder().getPrefix(), "{CLEAR}");

    assertNotNull(ds.getAllPasswordEncoders());
    assertFalse(ds.getAllPasswordEncoders().isEmpty());

    for (final String dn :
         new String[]
         {
           "uid=imported.unencoded,ou=People,dc=example,dc=com",
           "uid=imported.clear,ou=People,dc=example,dc=com",
           "uid=imported.hex,ou=People,dc=example,dc=com",
           "uid=imported.base64,ou=People,dc=example,dc=com",
           "uid=imported.sha,ou=People,dc=example,dc=com"
         })
    {
      final Entry entry = ds.getEntry(dn);
      assertNotNull(entry);

      assertNotNull(ds.getPasswordsInEntry(entry, null));
      assertFalse(ds.getPasswordsInEntry(entry, null).isEmpty());

      assertNotNull(ds.getPasswordsInEntry(entry,
           new ASN1OctetString("password")));
      assertFalse(ds.getPasswordsInEntry(entry,
           new ASN1OctetString("password")).isEmpty());

      assertNotNull(ds.getPasswordsInEntry(entry,
           new ASN1OctetString("wrong")));
      assertTrue(ds.getPasswordsInEntry(entry,
           new ASN1OctetString("wrong")).isEmpty());
    }


    // Get a connection and verify that we can authenticate as each of those
    // users with the right password, but not with the wrong password.
    final LDAPConnection conn = ds.getConnection();
    for (final String dn :
         new String[]
         {
           "uid=imported.unencoded,ou=People,dc=example,dc=com",
           "uid=imported.clear,ou=People,dc=example,dc=com",
           "uid=imported.hex,ou=People,dc=example,dc=com",
           "uid=imported.base64,ou=People,dc=example,dc=com",
           "uid=imported.sha,ou=People,dc=example,dc=com"
         })
    {
      assertResultCodeEquals(conn, new SimpleBindRequest(dn, "password"),
           ResultCode.SUCCESS);
      assertResultCodeEquals(conn, new SimpleBindRequest(dn, "wrong"),
           ResultCode.INVALID_CREDENTIALS);

      assertResultCodeEquals(conn, new PLAINBindRequest("dn:" + dn, "password"),
           ResultCode.SUCCESS);
      assertResultCodeEquals(conn, new SimpleBindRequest("dn:" + dn, "wrong"),
           ResultCode.INVALID_CREDENTIALS);
    }


    // Verify that we can't bind with the pre-encoded representation of the
    // password.
    assertResultCodeEquals(conn,
         new SimpleBindRequest("uid=imported.clear,ou=People,dc=example,dc=com",
              clearPassword),
         ResultCode.INVALID_CREDENTIALS);
    assertResultCodeEquals(conn,
         new SimpleBindRequest("uid=imported.hex,ou=People,dc=example,dc=com",
              hexPassword),
         ResultCode.INVALID_CREDENTIALS);
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=imported.base64,ou=People,dc=example,dc=com",
              base64Password),
         ResultCode.INVALID_CREDENTIALS);
    assertResultCodeEquals(conn,
         new SimpleBindRequest("uid=imported.sha,ou=People,dc=example,dc=com",
              shaPassword),
         ResultCode.INVALID_CREDENTIALS);


    // Verify that we can add a user with an unencoded password, that it
    // will be properly encoded, and that we can bind with that password.
    assertResultCodeEquals(conn,
         new AddRequest(
              "dn: uid=added.unencoded,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: added.unencoded",
              "givenName: Added",
              "sn: Unencoded",
              "cn: Added Unencoded",
              "userPassword: added"),
         ResultCode.SUCCESS);
    assertEquals(
         ds.getEntry("uid=added.unencoded,ou=People,dc=example,dc=com",
              "userPassword").getAttributeValue("userPassword"),
         "{CLEAR}added");
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=added.unencoded,ou=People,dc=example,dc=com", "added"),
         ResultCode.SUCCESS);


    // Verify that we can add a user with a pre-encoded password, and that it
    // will be left alone.
    final String hexOfAdded =
         "{HEX}" + StaticUtils.toHex(StaticUtils.getBytes("added"));
    assertResultCodeEquals(conn,
         new AddRequest(
              "dn: uid=added.hex,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: added.unencoded",
              "givenName: Added",
              "sn: Hex",
              "cn: Added Hex",
              "userPassword: " + hexOfAdded),
         ResultCode.SUCCESS);
    assertEquals(
         ds.getEntry("uid=added.hex,ou=People,dc=example,dc=com",
              "userPassword").getAttributeValue("userPassword"),
         hexOfAdded);
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=added.hex,ou=People,dc=example,dc=com", "added"),
         ResultCode.SUCCESS);


    // Verify that we can replace a password with a modify containing an
    // unencoded value and that it will behave properly.
    assertResultCodeEquals(conn,
         new ModifyRequest(
              "dn: uid=added.unencoded,ou=People,dc=example,dc=com",
              "changetype: modify",
              "replace: userPassword",
              "userPassword: replaced"),
         ResultCode.SUCCESS);
    assertEquals(
         ds.getEntry("uid=added.unencoded,ou=People,dc=example,dc=com",
              "userPassword").getAttributeValue("userPassword"),
         "{CLEAR}replaced");
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=added.unencoded,ou=People,dc=example,dc=com", "replaced"),
         ResultCode.SUCCESS);


    // Verify that we can replace a password with a modify containing an
    // encoded value and that it will behave properly.
    final String hexOfReplaced =
         "{HEX}" + StaticUtils.toHex(StaticUtils.getBytes("replaced"));
    assertResultCodeEquals(conn,
         new ModifyRequest(
              "dn: uid=added.hex,ou=People,dc=example,dc=com",
              "changetype: modify",
              "replace: userPassword",
              "userPassword: " + hexOfReplaced),
         ResultCode.SUCCESS);
    assertEquals(
         ds.getEntry("uid=added.hex,ou=People,dc=example,dc=com",
              "userPassword").getAttributeValue("userPassword"),
         hexOfReplaced);
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=added.hex,ou=People,dc=example,dc=com", "replaced"),
         ResultCode.SUCCESS);


    // Verify that we can perform a password change as a delete-then-add with
    // clear-text values.
    assertResultCodeEquals(conn,
         new ModifyRequest(
              "dn: uid=added.unencoded,ou=People,dc=example,dc=com",
              "changetype: modify",
              "delete: userPassword",
              "userPassword: replaced",
              "-",
              "add: userPassword",
              "userPassword: deleted-then-added"),
         ResultCode.SUCCESS);
    assertEquals(
         ds.getEntry("uid=added.unencoded,ou=People,dc=example,dc=com",
              "userPassword").getAttributeValue("userPassword"),
         "{CLEAR}deleted-then-added");
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=added.unencoded,ou=People,dc=example,dc=com",
              "deleted-then-added"),
         ResultCode.SUCCESS);


    // Verify that we can perform a password change as a delete-then-add with
    // pre-encoded values.  For the heck of it, we'll throw in an additional
    // modification that doesn't target a password attribute.
    final String hexOfDeletedThenAdded = "{HEX}" +
         StaticUtils.toHex(StaticUtils.getBytes("deleted-then-added"));
    assertResultCodeEquals(conn,
         new ModifyRequest(
              "dn: uid=added.hex,ou=People,dc=example,dc=com",
              "changetype: modify",
              "delete: userPassword",
              "userPassword: " + hexOfReplaced,
              "-",
              "add: userPassword",
              "userPassword: " + hexOfDeletedThenAdded,
              "-",
              "replace: description",
              "description: foo"),
         ResultCode.SUCCESS);
    assertEquals(
         ds.getEntry("uid=added.hex,ou=People,dc=example,dc=com",
              "userPassword").getAttributeValue("userPassword"),
         hexOfDeletedThenAdded);
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=added.hex,ou=People,dc=example,dc=com",
              "deleted-then-added"),
         ResultCode.SUCCESS);


    // Verify that we can't delete a nonexistent password value when we provide
    // the value in the clear.
    assertResultCodeEquals(conn,
         new ModifyRequest(
              "dn: uid=added.unencoded,ou=People,dc=example,dc=com",
              "changetype: modify",
              "delete: userPassword",
              "userPassword: nonexistent"),
         ResultCode.NO_SUCH_ATTRIBUTE);
    assertEquals(
         ds.getEntry("uid=added.unencoded,ou=People,dc=example,dc=com",
              "userPassword").getAttributeValue("userPassword"),
         "{CLEAR}deleted-then-added");
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=added.unencoded,ou=People,dc=example,dc=com",
              "deleted-then-added"),
         ResultCode.SUCCESS);
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=added.unencoded,ou=People,dc=example,dc=com",
              "nonexistent"),
         ResultCode.INVALID_CREDENTIALS);


    // Verify that we can't delete a nonexistent password value when we provide
    // the value in a pre-encoded form.
    final String hexOfNonexistent =
         "{HEX}" + StaticUtils.toHex(StaticUtils.getBytes("nonexistent"));
    assertResultCodeEquals(conn,
         new ModifyRequest(
              "dn: uid=added.hex,ou=People,dc=example,dc=com",
              "changetype: modify",
              "delete: userPassword",
              "userPassword: " + hexOfNonexistent),
         ResultCode.NO_SUCH_ATTRIBUTE);
    assertEquals(
         ds.getEntry("uid=added.hex,ou=People,dc=example,dc=com",
              "userPassword").getAttributeValue("userPassword"),
         hexOfDeletedThenAdded);
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=added.hex,ou=People,dc=example,dc=com",
              "deleted-then-added"),
         ResultCode.SUCCESS);
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=added.hex,ou=People,dc=example,dc=com",
              "nonexistent"),
         ResultCode.INVALID_CREDENTIALS);


    // Verify that we can't delete a password from an entry that doesn't have a
    // password.  Try the request first without any values to delete, and then
    // with a specific value.
    assertResultCodeEquals(conn,
         new ModifyRequest(
              "dn: dc=example,dc=com",
              "changetype: modify",
              "delete: userPassword"),
         ResultCode.NO_SUCH_ATTRIBUTE);
    assertResultCodeEquals(conn,
         new ModifyRequest(
              "dn: dc=example,dc=com",
              "changetype: modify",
              "delete: userPassword",
              "userPassword: nonexistent"),
         ResultCode.NO_SUCH_ATTRIBUTE);


    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests password encoding functionality for entries with multiple passwords.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultiplePasswords()
         throws Exception
  {
    // Create an in-memory directory server instance with support for a lot of
    // password encoders.
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    config.setPasswordEncoders(
         new ClearInMemoryPasswordEncoder("{CLEAR}", null));

    assertNotNull(config.getPasswordAttributes());
    assertFalse(config.getPasswordAttributes().isEmpty());
    assertEquals(config.getPasswordAttributes(),
         Collections.singleton("userPassword"));

    assertNotNull(config.getPrimaryPasswordEncoder());

    assertNotNull(config.getSecondaryPasswordEncoders());
    assertTrue(config.getSecondaryPasswordEncoders().isEmpty());

    assertNotNull(config.toString());

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
    ds.startListening();


    // Add some base entries to the server.
    final LDAPConnection conn = ds.getConnection();
    conn.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    conn.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");


    // Add an entry with multiple passwords in the clear.
    conn.add(
         "dn: uid=multiple.unencoded,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: multiple.unencoded",
         "givenName: Multiple",
         "sn: Unencoded",
         "cn: Multiple Unencoded",
         "userPassword: password1",
         "userPassword: password2");


    // Add an entry with multiple pre-encoded passwords.
    conn.add(
         "dn: uid=multiple.encoded,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: multiple.unencoded",
         "givenName: Multiple",
         "sn: Encoded",
         "cn: Multiple Encoded",
         "userPassword: {CLEAR}password1",
         "userPassword: {CLEAR}password2");


    // Verify that we can bind with both passwords for both users.
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=multiple.unencoded,ou=People,dc=example,dc=com",
              "password1"),
         ResultCode.SUCCESS);
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=multiple.unencoded,ou=People,dc=example,dc=com",
              "password2"),
         ResultCode.SUCCESS);
    assertResultCodeEquals(conn,
         new PLAINBindRequest(
              "dn:uid=multiple.unencoded,ou=People,dc=example,dc=com",
              "password1"),
         ResultCode.SUCCESS);
    assertResultCodeEquals(conn,
         new PLAINBindRequest(
              "dn:uid=multiple.unencoded,ou=People,dc=example,dc=com",
              "password2"),
         ResultCode.SUCCESS);

    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=multiple.encoded,ou=People,dc=example,dc=com",
              "password1"),
         ResultCode.SUCCESS);
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=multiple.encoded,ou=People,dc=example,dc=com",
              "password2"),
         ResultCode.SUCCESS);
    assertResultCodeEquals(conn,
         new PLAINBindRequest(
              "dn:uid=multiple.encoded,ou=People,dc=example,dc=com",
              "password1"),
         ResultCode.SUCCESS);
    assertResultCodeEquals(conn,
         new PLAINBindRequest(
              "dn:uid=multiple.encoded,ou=People,dc=example,dc=com",
              "password2"),
         ResultCode.SUCCESS);


    // Verify that we can modify the first user to remove just one of the
    // passwords and replace it with a different value.
    assertResultCodeEquals(conn,
         new ModifyRequest(
              "dn: uid=multiple.unencoded,ou=People,dc=example,dc=com",
              "changetype: modify",
              "delete: userPassword",
              "userPassword: password1",
              "-",
              "add: userPassword",
              "userPassword: password3"),
         ResultCode.SUCCESS);
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=multiple.unencoded,ou=People,dc=example,dc=com",
              "password1"),
         ResultCode.INVALID_CREDENTIALS);
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=multiple.unencoded,ou=People,dc=example,dc=com",
              "password2"),
         ResultCode.SUCCESS);
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=multiple.unencoded,ou=People,dc=example,dc=com",
              "password3"),
         ResultCode.SUCCESS);


    // Verify that we can use the password modify extended operation to
    // replace the password for the second user.
    assertResultCodeEquals(conn,
         new PasswordModifyExtendedRequest(
              "dn:uid=multiple.encoded,ou=People,dc=example,dc=com", null,
              "newPassword"),
         ResultCode.SUCCESS);
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=multiple.encoded,ou=People,dc=example,dc=com",
              "password1"),
         ResultCode.INVALID_CREDENTIALS);
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=multiple.encoded,ou=People,dc=example,dc=com",
              "password2"),
         ResultCode.INVALID_CREDENTIALS);
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=multiple.encoded,ou=People,dc=example,dc=com",
              "newPassword"),
         ResultCode.SUCCESS);


    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the behavior for a server configured without any password attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoPasswordAttributes()
         throws Exception
  {
    // Create an in-memory directory server instance with support for a lot of
    // password encoders.
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    final MessageDigest sha1Digest = CryptoHelper.getMessageDigest("SHA-1");
    config.setPasswordAttributes();
    config.setPasswordEncoders(
         new ClearInMemoryPasswordEncoder("{CLEAR}", null),
         new ClearInMemoryPasswordEncoder("{HEX}",
              HexPasswordEncoderOutputFormatter.getLowercaseInstance()),
         new ClearInMemoryPasswordEncoder("{BASE64}",
              Base64PasswordEncoderOutputFormatter.getInstance()),
         new UnsaltedMessageDigestInMemoryPasswordEncoder("{SHA}",
              Base64PasswordEncoderOutputFormatter.getInstance(), sha1Digest));

    assertNotNull(config.getPasswordAttributes());
    assertTrue(config.getPasswordAttributes().isEmpty());

    assertNotNull(config.getPrimaryPasswordEncoder());

    assertNotNull(config.getSecondaryPasswordEncoders());
    assertFalse(config.getSecondaryPasswordEncoders().isEmpty());

    assertNotNull(config.toString());

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
    ds.startListening();


    // Add some base entries to the server.
    final LDAPConnection conn = ds.getConnection();
    conn.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    conn.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");


    // Add an entry with a userPassword value.
    conn.add(
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


    // Verify that we can't perform a simple bind as the user.
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=test.user,ou=People,dc=example,dc=com",
              "password"),
         ResultCode.INVALID_CREDENTIALS);


    // Verify that we can't perform a SASL PLAIN bind as the user.
    assertResultCodeEquals(conn,
         new PLAINBindRequest(
              "dn:uid=test.user,ou=People,dc=example,dc=com",
              "password"),
         ResultCode.INVALID_CREDENTIALS);


    // Verify that we can't perform a password modify operation on the user
    // entry.
    assertResultCodeEquals(conn,
         new PasswordModifyExtendedRequest(
              "dn:uid=test.user,ou=People,dc=example,dc=com", null,
              "newPassword"),
         ResultCode.UNWILLING_TO_PERFORM);


    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the behavior for the case in which the server is only configured with
   * secondary password encoders but no primary encoder.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlySecondaryEncoders()
         throws Exception
  {
    // Create an in-memory directory server instance with support for a lot of
    // password encoders.
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    final MessageDigest sha1Digest = CryptoHelper.getMessageDigest("SHA-1");
    config.setPasswordEncoders(
         null,
         new ClearInMemoryPasswordEncoder("{CLEAR}", null),
         new ClearInMemoryPasswordEncoder("{HEX}",
              HexPasswordEncoderOutputFormatter.getLowercaseInstance()),
         new ClearInMemoryPasswordEncoder("{BASE64}",
              Base64PasswordEncoderOutputFormatter.getInstance()),
         new UnsaltedMessageDigestInMemoryPasswordEncoder("{SHA}",
              Base64PasswordEncoderOutputFormatter.getInstance(), sha1Digest));

    assertNotNull(config.getPasswordAttributes());
    assertFalse(config.getPasswordAttributes().isEmpty());
    assertEquals(config.getPasswordAttributes(),
         Collections.singleton("userPassword"));

    assertNull(config.getPrimaryPasswordEncoder());

    assertNotNull(config.getSecondaryPasswordEncoders());
    assertFalse(config.getSecondaryPasswordEncoders().isEmpty());

    assertNotNull(config.toString());

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
    ds.startListening();


    // Add some base entries to the server.
    final LDAPConnection conn = ds.getConnection();
    conn.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    conn.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");


    // Add an entry with a userPassword value in the clear.  Make sure that it
    // remains in the clear and that we can use it to bind.
    conn.add(
         "dn: uid=test.unencoded,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.unencoded",
         "givenName: Test",
         "sn: Unencoded",
         "cn: Test Unencoded",
         "userPassword: password");
    assertEquals(
         ds.getEntry("uid=test.unencoded,ou=People,dc=example,dc=com",
              "userPassword").getAttributeValue("userPassword"),
         "password");
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=test.unencoded,ou=People,dc=example,dc=com",
              "password"),
         ResultCode.SUCCESS);
    assertResultCodeEquals(conn,
         new PLAINBindRequest(
              "dn:uid=test.unencoded,ou=People,dc=example,dc=com",
              "password"),
         ResultCode.SUCCESS);


    // Add an entry with a pre-encoded userPassword value.  Make sure that it
    // stays pre-encoded and that we can also use it to bind.
    final String hexPassword =
         "{HEX}" + StaticUtils.toHex(StaticUtils.getBytes("password"));
    conn.add(
         "dn: uid=test.encoded,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.encoded",
         "givenName: Test",
         "sn: Encoded",
         "cn: Test Encoded",
         "userPassword: " + hexPassword);
    assertEquals(
         ds.getEntry("uid=test.encoded,ou=People,dc=example,dc=com",
              "userPassword").getAttributeValue("userPassword"),
         hexPassword);
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=test.encoded,ou=People,dc=example,dc=com",
              "password"),
         ResultCode.SUCCESS);
    assertResultCodeEquals(conn,
         new PLAINBindRequest(
              "dn:uid=test.encoded,ou=People,dc=example,dc=com",
              "password"),
         ResultCode.SUCCESS);


    // Modify the entry with the unencoded password to use a different unencoded
    // password.  Verify that it is updated properly and the new password can
    // be used.
    conn.modify(
         "dn: uid=test.unencoded,ou=People,dc=example,dc=com",
         "changetype: modify",
         "delete: userPassword",
         "userPassword: password",
         "-",
         "add: userPassword",
         "userPassword: newPassword");
    assertEquals(
         ds.getEntry("uid=test.unencoded,ou=People,dc=example,dc=com",
              "userPassword").getAttributeValue("userPassword"),
         "newPassword");
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=test.unencoded,ou=People,dc=example,dc=com",
              "newPassword"),
         ResultCode.SUCCESS);
    assertResultCodeEquals(conn,
         new PLAINBindRequest(
              "dn:uid=test.unencoded,ou=People,dc=example,dc=com",
              "newPassword"),
         ResultCode.SUCCESS);


    // Modify the entry with the encoded password to use a different encoded
    // password.  Verify that it is updated properly and the new password can
    // be used.
    final String hexNewPassword =
         "{HEX}" + StaticUtils.toHex(StaticUtils.getBytes("newPassword"));
    conn.modify(
         "dn: uid=test.encoded,ou=People,dc=example,dc=com",
         "changetype: modify",
         "delete: userPassword",
         "userPassword: " + hexPassword,
         "-",
         "add: userPassword",
         "userPassword: " + hexNewPassword);
    assertEquals(
         ds.getEntry("uid=test.encoded,ou=People,dc=example,dc=com",
              "userPassword").getAttributeValue("userPassword"),
         hexNewPassword);
    assertResultCodeEquals(conn,
         new SimpleBindRequest(
              "uid=test.encoded,ou=People,dc=example,dc=com",
              "newPassword"),
         ResultCode.SUCCESS);
    assertResultCodeEquals(conn,
         new PLAINBindRequest(
              "dn:uid=test.encoded,ou=People,dc=example,dc=com",
              "newPassword"),
         ResultCode.SUCCESS);


    conn.close();
    ds.shutDown(true);
  }
}
