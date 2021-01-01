/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.monitors;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the
 * ReplicationSummaryReplicationServer class.
 */
public class ReplicationSummaryReplicationServerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a valid string with all fields present and containing valid values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllFieldsValid()
         throws Exception
  {
    String s =
         "server-id=\"12345\" server=\"directory.example.com:8989\" " +
         "generation-id=\"1234567\" status=\"operational\" " +
             "last-connected=\"Thu Apr 08 08:45:59 CDT 2010\" " +
             "last-failed=\"Thu Apr 08 08:45:58 CDT 2010\" " +
             "failed-attempts=\"0\"";

    ReplicationSummaryReplicationServer server =
         new ReplicationSummaryReplicationServer(s);
    assertNotNull(server);

    assertNotNull(server.getReplicationServerID());
    assertEquals(server.getReplicationServerID(), "12345");

    assertNotNull(server.getReplicationServerAddress());
    assertEquals(server.getReplicationServerAddress(), "directory.example.com");

    assertNotNull(server.getReplicationServerPort());
    assertEquals(server.getReplicationServerPort(), Long.valueOf(8989));

    assertNotNull(server.getGenerationID());
    assertEquals(server.getGenerationID(), "1234567");

    assertNotNull(server.getReplicationServerStatus());
    assertEquals(server.getReplicationServerStatus(), "operational");

    assertNotNull(server.getReplicationServerLastConnected());
    assertEquals(
        server.getReplicationServerLastConnected().toString(),
        "Thu Apr 08 08:45:59 CDT 2010"
    );

    assertNotNull(server.getReplicationServerLastFailed());
    assertEquals(
        server.getReplicationServerLastFailed().toString(),
        "Thu Apr 08 08:45:58 CDT 2010"
    );

    assertNotNull(server.getReplicationServerFailedAttempts());
    assertEquals(server.getReplicationServerFailedAttempts(),
         Long.valueOf("0"));

    assertNotNull(server.toString());
    assertEquals(server.toString(), s);
  }



  /**
   * Tests a valid string with all fields present but empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllFieldsEmpty()
         throws Exception
  {
    String s = "server-id=\"\" server=\"\" generation-id=\"\" status=\"\" " +
        "last-connected=\"\" last-failed=\"\" failed-attempts=\"\"";

    ReplicationSummaryReplicationServer server =
         new ReplicationSummaryReplicationServer(s);
    assertNotNull(server);

    assertNull(server.getReplicationServerID());

    assertNull(server.getReplicationServerAddress());

    assertNull(server.getReplicationServerPort());

    assertNull(server.getGenerationID());

    assertNull(server.getReplicationServerStatus());

    assertNull(server.getReplicationServerLastConnected());

    assertNull(server.getReplicationServerLastFailed());

    assertNull(server.getReplicationServerFailedAttempts());

    assertNotNull(server.toString());
    assertEquals(server.toString(), s);
  }



  /**
   * Tests a valid string with all fields present, but some of them having
   * invalid values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllFieldsSomeInvalid()
         throws Exception
  {
    String s =
         "server-id=\"12345\" server=\"invalid\" " +
         "generation-id=\"1234567\" status=\"operational\" " +
         "last-connected=\"invalid\" " +
         "last-failed=\"Thu Apr 08 08:45:58 CDT 2010\" " +
         "failed-attempts=\"invalid\"";

    ReplicationSummaryReplicationServer server =
         new ReplicationSummaryReplicationServer(s);
    assertNotNull(server);

    assertNotNull(server.getReplicationServerID());
    assertEquals(server.getReplicationServerID(), "12345");

    assertNull(server.getReplicationServerAddress());

    assertNull(server.getReplicationServerPort());

    assertNotNull(server.getGenerationID());
    assertEquals(server.getGenerationID(), "1234567");

    assertNotNull(server.getReplicationServerStatus());
    assertEquals(server.getReplicationServerStatus(), "operational");

    assertNull(server.getReplicationServerLastConnected());

    assertNotNull(server.getReplicationServerLastFailed());
    assertEquals(
        server.getReplicationServerLastFailed().toString(),
        "Thu Apr 08 08:45:58 CDT 2010"
    );

    assertNull(server.getReplicationServerFailedAttempts());

    assertNotNull(server.toString());
    assertEquals(server.toString(), s);
  }



  /**
   * Tests an empty string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyString()
         throws Exception
  {
    String s = "";

    ReplicationSummaryReplicationServer server =
         new ReplicationSummaryReplicationServer(s);
    assertNotNull(server);

    assertNull(server.getReplicationServerID());

    assertNull(server.getReplicationServerAddress());

    assertNull(server.getReplicationServerPort());

    assertNull(server.getGenerationID());

    assertNull(server.getReplicationServerStatus());

    assertNull(server.getReplicationServerLastConnected());

    assertNull(server.getReplicationServerLastFailed());

    assertNull(server.getReplicationServerFailedAttempts());

    assertNotNull(server.toString());
    assertEquals(server.toString(), s);
  }



  /**
   * Tests a non-empty string that doesn't have anything to do with a
   * replication summary replica.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonRelevantString()
         throws Exception
  {
    String s = "The quick brown fox jumps over the lazy dog";

    ReplicationSummaryReplicationServer server =
         new ReplicationSummaryReplicationServer(s);
    assertNotNull(server);

    assertNull(server.getReplicationServerID());

    assertNull(server.getReplicationServerAddress());

    assertNull(server.getReplicationServerPort());

    assertNull(server.getGenerationID());

    assertNull(server.getReplicationServerStatus());

    assertNull(server.getReplicationServerLastConnected());

    assertNull(server.getReplicationServerLastFailed());

    assertNull(server.getReplicationServerFailedAttempts());

    assertNotNull(server.toString());
    assertEquals(server.toString(), s);
  }
}
