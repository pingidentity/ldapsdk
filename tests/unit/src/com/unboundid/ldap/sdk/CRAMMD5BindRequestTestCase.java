/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.util.ArrayList;
import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;



/**
 * This class provides a set of test cases for the CRAMMD5BindRequest class.
 */
public class CRAMMD5BindRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    CRAMMD5BindRequest r = new CRAMMD5BindRequest("u:test.user", "password");
    r = r.duplicate();

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertEquals(r.getBindType(), "CRAM-MD5");

    assertEquals(r.getSASLMechanismName(), "CRAM-MD5");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    CRAMMD5BindRequest);

    r.getLastMessageID();

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the second constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    CRAMMD5BindRequest r = new CRAMMD5BindRequest("u:test.user",
                                                  "password".getBytes("UTF-8"));
    r = r.duplicate();

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertEquals(r.getBindType(), "CRAM-MD5");

    assertEquals(r.getSASLMechanismName(), "CRAM-MD5");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    CRAMMD5BindRequest);

    r.getLastMessageID();

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the third constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    CRAMMD5BindRequest r =
         new CRAMMD5BindRequest("u:test.user", new ASN1OctetString("password"));
    r = r.duplicate();

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertEquals(r.getBindType(), "CRAM-MD5");

    assertEquals(r.getSASLMechanismName(), "CRAM-MD5");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    CRAMMD5BindRequest);

    r.getLastMessageID();

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the fourth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    CRAMMD5BindRequest r =
         new CRAMMD5BindRequest("u:test.user", "password", controls);
    r = r.duplicate();

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertEquals(r.getBindType(), "CRAM-MD5");

    assertEquals(r.getSASLMechanismName(), "CRAM-MD5");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    CRAMMD5BindRequest);

    r.getLastMessageID();

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the fifth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    CRAMMD5BindRequest r = new CRAMMD5BindRequest("u:test.user",
         "password".getBytes("UTF-8"), controls);
    r = r.duplicate();

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertEquals(r.getBindType(), "CRAM-MD5");

    assertEquals(r.getSASLMechanismName(), "CRAM-MD5");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    CRAMMD5BindRequest);

    r.getLastMessageID();

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the sixth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    CRAMMD5BindRequest r = new CRAMMD5BindRequest("u:test.user",
         new ASN1OctetString("password"), controls);
    r = r.duplicate();

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertEquals(r.getBindType(), "CRAM-MD5");

    assertEquals(r.getSASLMechanismName(), "CRAM-MD5");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    CRAMMD5BindRequest);

    r.getLastMessageID();

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the ability of the LDAP SDK to send a SASL CRAM-MD5 bind request to
   * authenticate as an admin user, and receive the corresponding result.
   * <BR><BR>
   * Access to a Directory Server instance running on the local system is
   * required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendCRAMMD5Bind()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }


    // Add test data, including a custom password policy that will store
    // passwords in a reversible format.
    final LDAPConnection conn = getAdminConnection();

    try
    {
      conn.add(getTestBaseDN(), getBaseEntryAttributes());

      conn.add(
           "dn: cn=Reversible Password Policy," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: ds-cfg-password-policy",
           "cn: Reversible Password Policy",
           "ds-cfg-password-attribute: userPassword",
           "ds-cfg-default-password-storage-scheme: cn=AES," +
                "cn=Password Storage Schemes,cn=config");

      conn.add(
           "dn: uid=test," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: test",
           "givenName: Test",
           "sn: User",
           "cn: Test User",
           "userPassword: password",
           "ds-pwp-password-policy-dn: cn=Reversible Password Policy," +
                getTestBaseDN());

      CRAMMD5BindRequest bindRequest =
           new CRAMMD5BindRequest("dn:uid=test," + getTestBaseDN(), "password");
      BindResult bindResult = conn.bind(bindRequest);
      assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);
      bindRequest.getLastMessageID();
    }
    finally
    {
      conn.bind(getTestBindDN(), getTestBindPassword());

      try
      {
        conn.delete("uid=test," + getTestBaseDN());
      } catch (final Exception e) {}

      try
      {
      } catch (final Exception e) {}

      try
      {
        conn.delete("cn=Reversible Password Policy," + getTestBaseDN());
      } catch (final Exception e) {}

      try
      {
        conn.delete(getTestBaseDN());
      } catch (final Exception e) {}

      conn.close();
    }
  }
}
