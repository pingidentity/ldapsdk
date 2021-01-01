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



import java.util.ArrayList;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.protocol.BindRequestProtocolOp;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the certificate plus password
 * SASL bind request.
 */
public final class UnboundIDCertificatePlusPasswordBindRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with a string password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordString()
         throws Exception
  {
    UnboundIDCertificatePlusPasswordBindRequest r =
         new UnboundIDCertificatePlusPasswordBindRequest("password");

    r = r.duplicate();
    assertNotNull(r);

    r = r.getRebindRequest("localhost", 389);
    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(),
         "UNBOUNDID-CERTIFICATE-PLUS-PASSWORD");

    assertNotNull(r.getPassword());
    assertEquals(r.getPassword().getType(),
         BindRequestProtocolOp.CRED_TYPE_SASL);
    assertEquals(r.getPassword().stringValue(),
         "password");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertEquals(r.getLastMessageID(), -1);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the behavior with a password byte array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordBytes()
         throws Exception
  {
    UnboundIDCertificatePlusPasswordBindRequest r =
         new UnboundIDCertificatePlusPasswordBindRequest(
              "pwbytes".getBytes("UTF-8"),
              new Control("1.2.3.4"), new Control("1.2.3.5", true));

    r = r.duplicate();
    assertNotNull(r);

    r = r.getRebindRequest("localhost", 389);
    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(),
         "UNBOUNDID-CERTIFICATE-PLUS-PASSWORD");

    assertNotNull(r.getPassword());
    assertEquals(r.getPassword().getType(),
         BindRequestProtocolOp.CRED_TYPE_SASL);
    assertEquals(r.getPassword().stringValue(),
         "pwbytes");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertEquals(r.getLastMessageID(), -1);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the behavior with a null password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullPassword()
         throws Exception
  {
    new UnboundIDCertificatePlusPasswordBindRequest((String) null);
  }



  /**
   * Tests the behavior with an empty password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEmptyPassword()
         throws Exception
  {
    new UnboundIDCertificatePlusPasswordBindRequest("");
  }



  /**
   * Tests the behavior when trying to send the request to the in-memory
   * directory server.  The server doesn't support this mechanism, but this is
   * good enough to get code coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequest()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    final UnboundIDCertificatePlusPasswordBindRequest r =
         new UnboundIDCertificatePlusPasswordBindRequest("password");
    assertEquals(r.getLastMessageID(), -1);

    assertResultCodeEquals(conn, r, ResultCode.AUTH_METHOD_NOT_SUPPORTED);
    assertTrue(r.getLastMessageID() > 0);

    conn.close();
  }
}
