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



import java.util.Date;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides a set of test cases for the ReplicationSummaryReplica
 * class.
 */
public class ReplicationSummaryReplicaTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a valid string with all fields present and containing valid values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testAllFieldsValid()
         throws Exception
  {
    Date d = new Date(System.currentTimeMillis() - 10000L);

    String s =
         "replica-id=\"12345\" ldap-server=\"directory.example.com:389\" " +
         "connected-to=\"54321\" generation-id=\"1234567\" " +
         "replication-backlog=\"12\" recent-update-rate=\"123/sec\" " +
         "peak-update-rate=\"321/sec\" age-of-oldest-backlog-change=\"" +
         encodeGeneralizedTime(d) + " (behind by 10 seconds)\"";

    ReplicationSummaryReplica r = new ReplicationSummaryReplica(s);
    assertNotNull(r);

    assertNotNull(r.getReplicaID());
    assertEquals(r.getReplicaID(), "12345");

    assertNotNull(r.getLDAPServerAddress());
    assertEquals(r.getLDAPServerAddress(), "directory.example.com");

    assertNotNull(r.getLDAPServerPort());
    assertEquals(r.getLDAPServerPort(), Long.valueOf(389));

    assertNotNull(r.getReplicationServerID());
    assertEquals(r.getReplicationServerID(), "54321");

    assertNotNull(r.getGenerationID());
    assertEquals(r.getGenerationID(), "1234567");

    assertNotNull(r.getReplicationBacklog());
    assertEquals(r.getReplicationBacklog(), Long.valueOf(12));
    // Checks client-side backwards compatibility.
    assertEquals(r.getReplicationBacklog(), r.getMissingChanges());

    assertNotNull(r.getRecentUpdateRate());
    assertEquals(r.getRecentUpdateRate(), Long.valueOf(123));

    assertNotNull(r.getPeakUpdateRate());
    assertEquals(r.getPeakUpdateRate(), Long.valueOf(321));

    assertNotNull(r.getOldestBacklogChangeDate());
    assertEquals(r.getOldestBacklogChangeDate(), d);
    // Checks client-side backwards compatibility.
    assertEquals(r.getOldestBacklogChangeDate(),
                 r.getOldestMissingChangeDate());

    assertNotNull(r.toString());
    assertEquals(r.toString(), s);
  }



  /**
   * Tests whether the SDK correctly parses out missing-changes (which
   * is currently known as replication-backlog) and age-of-oldest-missing-change
   * (which is currently known as age-of-oldest-backlog-change).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMissingChangesBackwardsCompatibility()
         throws Exception
  {
    Date d = new Date(System.currentTimeMillis() - 10000L);

    String s =
         "replica-id=\"12345\" ldap-server=\"directory.example.com:389\" " +
         "connected-to=\"54321\" generation-id=\"1234567\" " +
         "missing-changes=\"12\" recent-update-rate=\"123/sec\" " +
         "peak-update-rate=\"321/sec\" age-of-oldest-missing-change=\"" +
         encodeGeneralizedTime(d) + " (behind by 10 seconds)\"";

    ReplicationSummaryReplica r = new ReplicationSummaryReplica(s);
    assertNotNull(r);

    assertNotNull(r.getReplicationBacklog());
    assertEquals(r.getReplicationBacklog(), Long.valueOf(12));

    assertNotNull(r.getOldestBacklogChangeDate());
    assertEquals(r.getOldestBacklogChangeDate(), d);
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
    String s =
         "replica-id=\"\" ldap-server=\"\" connected-to=\"\" " +
         "generation-id=\"\" replication-backlog=\"\" " +
         "recent-update-rate=\"\" peak-update-rate=\"\" " +
         "age-of-oldest-backlog-change=\"\"";

    ReplicationSummaryReplica r = new ReplicationSummaryReplica(s);
    assertNotNull(r);

    assertNull(r.getReplicaID(), r.getReplicaID());

    assertNull(r.getLDAPServerAddress());

    assertNull(r.getLDAPServerPort());

    assertNull(r.getReplicationServerID());

    assertNull(r.getGenerationID());

    assertNull(r.getReplicationBacklog());

    assertNull(r.getRecentUpdateRate());

    assertNull(r.getPeakUpdateRate());

    assertNull(r.getOldestBacklogChangeDate());

    assertNotNull(r.toString());
    assertEquals(r.toString(), s);
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
         "replica-id=\"12345\" ldap-server=\"invalid\" " +
         "connected-to=\"54321\" generation-id=\"1234567\" " +
         "replication-backlog=\"invalid\" recent-update-rate=\"invalid\" " +
         "peak-update-rate=\"invalid\" " +
         "age-of-oldest-backlog-change=\"invalid\"";

    ReplicationSummaryReplica r = new ReplicationSummaryReplica(s);
    assertNotNull(r);

    assertNotNull(r.getReplicaID());
    assertEquals(r.getReplicaID(), "12345");

    assertNull(r.getLDAPServerAddress());

    assertNull(r.getLDAPServerPort());

    assertNotNull(r.getReplicationServerID());
    assertEquals(r.getReplicationServerID(), "54321");

    assertNotNull(r.getGenerationID());
    assertEquals(r.getGenerationID(), "1234567");

    assertNull(r.getReplicationBacklog());

    assertNull(r.getRecentUpdateRate());

    assertNull(r.getPeakUpdateRate());

    assertNull(r.getOldestBacklogChangeDate());

    assertNotNull(r.toString());
    assertEquals(r.toString(), s);
  }



  /**
   * Tests an emtpy string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyString()
         throws Exception
  {
    String s = "";

    ReplicationSummaryReplica r = new ReplicationSummaryReplica(s);
    assertNotNull(r);

    assertNull(r.getReplicaID());

    assertNull(r.getLDAPServerAddress());

    assertNull(r.getLDAPServerPort());

    assertNull(r.getReplicationServerID());

    assertNull(r.getGenerationID());

    assertNull(r.getReplicationBacklog());

    assertNull(r.getRecentUpdateRate());

    assertNull(r.getPeakUpdateRate());

    assertNull(r.getOldestBacklogChangeDate());

    assertNotNull(r.toString());
    assertEquals(r.toString(), s);
  }



  /**
   * Tests a non-emtpy string that doesn't have anything to do with a
   * replication summary replica.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonRelevantString()
         throws Exception
  {
    String s = "The quick brown fox jumps over the lazy dog";

    ReplicationSummaryReplica r = new ReplicationSummaryReplica(s);
    assertNotNull(r);

    assertNull(r.getReplicaID());

    assertNull(r.getLDAPServerAddress());

    assertNull(r.getLDAPServerPort());

    assertNull(r.getReplicationServerID());

    assertNull(r.getGenerationID());

    assertNull(r.getReplicationBacklog());

    assertNull(r.getRecentUpdateRate());

    assertNull(r.getPeakUpdateRate());

    assertNull(r.getOldestBacklogChangeDate());

    assertNotNull(r.toString());
    assertEquals(r.toString(), s);
  }
}
