/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the SCRAM-SHA-1 bind request.
 */
public final class SCRAMSHA1BindRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when using a username with a string password and no
   * controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsernameWithStringPasswordNoControls()
         throws Exception
  {
    final SCRAMSHA1BindRequest r = new SCRAMSHA1BindRequest("user", "pencil");

    assertNotNull(r.getUsername());
    assertEquals(r.getUsername(), "user");

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "pencil");

    assertNotNull(r.getPasswordBytes());
    assertEquals(r.getPasswordBytes(), StaticUtils.getBytes("pencil"));

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "SCRAM-SHA-1");

    assertNotNull(r.getDigestAlgorithmName());
    assertEquals(r.getDigestAlgorithmName(), "SHA-1");

    assertNotNull(r.getMACAlgorithmName());
    assertEquals(r.getMACAlgorithmName(), "HmacSHA1");

    assertNotNull(r.getRebindRequest("localhost", 389));
    assertTrue(
         r.getRebindRequest("localhost", 389) instanceof SCRAMSHA1BindRequest);

    assertNotNull(r.duplicate());
    assertTrue(r.duplicate() instanceof SCRAMSHA1BindRequest);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.toString());

    final List<String> lineList = new ArrayList<>();
    r.toCode(lineList, "X", 4, true);

    assertNotNull(r.getMac(StaticUtils.byteArray(1, 2, 3, 4)));

    assertNotNull(r.digest(StaticUtils.byteArray(1, 2, 3, 4)));
  }



  /**
   * Tests the behavior when using a username with a password as a byte array
   * and a set of request controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsernameWithByteArrayPasswordWithControls()
         throws Exception
  {
    final SCRAMSHA1BindRequest r = new SCRAMSHA1BindRequest("user",
         StaticUtils.getBytes("pencil"), new Control("1.2.3.4"),
         new Control("5.6.7.8"));

    assertNotNull(r.getUsername());
    assertEquals(r.getUsername(), "user");

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "pencil");

    assertNotNull(r.getPasswordBytes());
    assertEquals(r.getPasswordBytes(), StaticUtils.getBytes("pencil"));

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "SCRAM-SHA-1");

    assertNotNull(r.getDigestAlgorithmName());
    assertEquals(r.getDigestAlgorithmName(), "SHA-1");

    assertNotNull(r.getMACAlgorithmName());
    assertEquals(r.getMACAlgorithmName(), "HmacSHA1");

    assertNotNull(r.getRebindRequest("localhost", 389));
    assertTrue(
         r.getRebindRequest("localhost", 389) instanceof SCRAMSHA1BindRequest);

    assertNotNull(r.duplicate());
    assertTrue(r.duplicate() instanceof SCRAMSHA1BindRequest);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.toString());

    final List<String> lineList = new ArrayList<>();
    r.toCode(lineList, "X", 4, true);

    assertNotNull(r.getMac(StaticUtils.byteArray(1, 2, 3, 4)));

    assertNotNull(r.digest(StaticUtils.byteArray(1, 2, 3, 4)));
  }



  /**
   * Tests the behavior when trying to process the bind in a server that doesn't
   * support it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcessBindMechanismNotSupported()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    try (LDAPConnection conn = ds.getConnection())
    {
      assertResultCodeNot(conn,
           new SCRAMSHA1BindRequest("test.user", "password"),
           ResultCode.SUCCESS);
    }
  }



  /**
   * Tests the behavior when trying to process the bind in an in-memory
   * directory server with a very simple handler that should support enough of
   * what we need for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcessBindMechanismSupported()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addSASLBindHandler(
         new TestSCRAMSHA1InMemorySASLBindHandler("password"));

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();
    try (LDAPConnection conn = ds.getConnection())
    {
      assertResultCodeEquals(conn,
           new SCRAMSHA1BindRequest("test.user", "password"),
           ResultCode.SUCCESS);

      assertResultCodeEquals(conn,
           new SCRAMSHA1BindRequest("test.user", "wrong"),
           ResultCode.INVALID_CREDENTIALS);
    }
    finally
    {
      ds.shutDown(true);
    }
  }
}
