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
package com.unboundid.ldap.sdk.unboundidds.controls;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the assured replication server
 * result class.
 */
public final class AssuredReplicationServerResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a version of the class with both a replication server ID and a
   * replica ID provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithReplicationServerIDAndReplicaID()
         throws Exception
  {
    AssuredReplicationServerResult r = new AssuredReplicationServerResult(
         AssuredReplicationServerResultCode.COMPLETE, (short) 1234,
         (short) 5678);

    r = AssuredReplicationServerResult.decode(r.encode());
    assertNotNull(r);

    assertEquals(r.getResultCode(),
         AssuredReplicationServerResultCode.COMPLETE);

    assertEquals(r.getReplicationServerID().shortValue(), (short) 1234);

    assertEquals(r.getReplicaID().shortValue(), (short) 5678);

    assertNotNull(r.toString());
  }



  /**
   * Tests a version of the class without either a replication server ID or a
   * replica ID provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutReplicationServerIDAndReplicaID()
         throws Exception
  {
    AssuredReplicationServerResult r = new AssuredReplicationServerResult(
         AssuredReplicationServerResultCode.TIMEOUT, null, null);

    r = AssuredReplicationServerResult.decode(r.encode());
    assertNotNull(r);

    assertEquals(r.getResultCode(),
         AssuredReplicationServerResultCode.TIMEOUT);

    assertNull(r.getReplicationServerID());

    assertNull(r.getReplicaID());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode an ASN.1 element that isn't a
   * valid sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    AssuredReplicationServerResult.decode(new ASN1OctetString("foo"));
  }



  /**
   * Tests the behavior when trying to decode an ASN.1 element that is a
   * sequence that does not have a result code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceMissingResultCode()
         throws Exception
  {
    final ASN1Sequence resultSequence = new ASN1Sequence(
         new ASN1Integer((byte) 0x81, 1234));

    AssuredReplicationServerResult.decode(resultSequence);
  }



  /**
   * Tests the behavior when trying to decode an ASN.1 element that is a
   * sequence containing an unrecognized result code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceInvalidResultCode()
         throws Exception
  {
    final ASN1Sequence resultSequence = new ASN1Sequence(
         new ASN1Enumerated((byte) 0x80, 1234),
         new ASN1Integer((byte) 0x81, 5678));

    AssuredReplicationServerResult.decode(resultSequence);
  }



  /**
   * Tests the behavior when trying to decode an ASN.1 element that is a
   * sequence that has an unexpected element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceUnexpectedElementType()
         throws Exception
  {
    final ASN1Sequence resultSequence = new ASN1Sequence(
         new ASN1Enumerated((byte) 0x80, 0),
         new ASN1Enumerated((byte) 0x81, 1234),
         new ASN1Enumerated((byte) 0x85, 5678));

    AssuredReplicationServerResult.decode(resultSequence);
  }
}
