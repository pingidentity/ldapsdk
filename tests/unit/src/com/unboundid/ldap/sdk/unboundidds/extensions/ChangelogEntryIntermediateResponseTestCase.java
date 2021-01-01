/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.Arrays;
import java.util.UUID;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.ChangeLogEntry;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.unboundidds.UnboundIDChangeLogEntry;
import com.unboundid.util.Base64;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the
 * {@code ChangelogEntryIntermediateResponse} class.
 */
public final class ChangelogEntryIntermediateResponseTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides generic coverage for a changelog entry intermediate response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntryResponseWithGenericChangelogEntry()
         throws Exception
  {
    final StringBuilder changes = new StringBuilder();
    changes.append("objectClass: top").append(StaticUtils.EOL);
    changes.append("objectClass: domain").append(StaticUtils.EOL);
    changes.append("dc: example").append(StaticUtils.EOL);

    final ChangeLogEntry e = new ChangeLogEntry(new Entry(
       "dn: changeNumber=1,cn=changelog",
       "objectClass: top",
       "objectClass: changeLogEntry",
       "changeNumber: 1",
       "targetDN: dc=example,dc=com",
       "changeType: add",
       "changes:: " + Base64.encode(changes.toString())));

    final String serverID = UUID.randomUUID().toString();

    final ASN1OctetString resumeToken = new ASN1OctetString("foo");

    ChangelogEntryIntermediateResponse ir =
         new ChangelogEntryIntermediateResponse(e, serverID, resumeToken,
              new Control("1.2.3.4"), new Control("5.6.7.8"));
    ir = new ChangelogEntryIntermediateResponse(ir);

    assertNotNull(ir);

    assertNotNull(ir.getChangeLogEntry());
    assertEquals(ir.getChangeLogEntry(), e);

    assertNotNull(ir.getServerID());
    assertEquals(ir.getServerID(), serverID);

    assertNotNull(ir.getResumeToken());
    assertTrue(Arrays.equals(ir.getResumeToken().getValue(),
         resumeToken.getValue()));

    assertNotNull(ir.getIntermediateResponseName());

    assertNotNull(ir.valueToString());

    assertNotNull(ir.toString());
  }



  /**
   * Provides generic coverage for a changelog entry intermediate response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntryResponseWithUnboundIDChangelogEntry()
         throws Exception
  {
    final StringBuilder changes = new StringBuilder();
    changes.append("objectClass: top").append(StaticUtils.EOL);
    changes.append("objectClass: domain").append(StaticUtils.EOL);
    changes.append("dc: example").append(StaticUtils.EOL);

    final ChangeLogEntry e = new UnboundIDChangeLogEntry(new Entry(
       "dn: changeNumber=1,cn=changelog",
       "objectClass: top",
       "objectClass: changeLogEntry",
       "changeNumber: 1",
       "targetDN: dc=example,dc=com",
       "changeType: add",
       "changes:: " + Base64.encode(changes.toString())));

    final String serverID = UUID.randomUUID().toString();

    final ASN1OctetString resumeToken = new ASN1OctetString("foo");

    ChangelogEntryIntermediateResponse ir =
         new ChangelogEntryIntermediateResponse(e, serverID, resumeToken,
              new Control("1.2.3.4"), new Control("5.6.7.8"));
    ir = new ChangelogEntryIntermediateResponse(ir);

    assertNotNull(ir);

    assertNotNull(ir.getChangeLogEntry());
    assertEquals(ir.getChangeLogEntry(), e);

    assertNotNull(ir.getServerID());
    assertEquals(ir.getServerID(), serverID);

    assertNotNull(ir.getResumeToken());
    assertTrue(Arrays.equals(ir.getResumeToken().getValue(),
         resumeToken.getValue()));

    assertNotNull(ir.getIntermediateResponseName());

    assertNotNull(ir.valueToString());

    assertNotNull(ir.toString());
  }



  /**
   * Tests the behavior when attempting to decode an intermediate response
   * without a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class})
  public void testDecodeNoValue()
         throws Exception
  {
    new ChangelogEntryIntermediateResponse(new IntermediateResponse(
         ChangelogEntryIntermediateResponse.
              CHANGELOG_ENTRY_INTERMEDIATE_RESPONSE_OID, null));
  }



  /**
   * Tests the behavior when attempting to decode an intermediate response
   * with a value that cannot be parse as a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class})
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new ChangelogEntryIntermediateResponse(new IntermediateResponse(
         ChangelogEntryIntermediateResponse.
              CHANGELOG_ENTRY_INTERMEDIATE_RESPONSE_OID,
         new ASN1OctetString("foo")));
  }



  /**
   * Tests the behavior when attempting to decode an intermediate response
   * with a value sequence with an unexpected number of elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class})
  public void testDecodeValueSequenceInvalidElementCount()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString("foo"));

    new ChangelogEntryIntermediateResponse(new IntermediateResponse(
         ChangelogEntryIntermediateResponse.
              CHANGELOG_ENTRY_INTERMEDIATE_RESPONSE_OID,
         new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the behavior when attempting to decode an intermediate response
   * with a value sequence with a value sequence containing malformed elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class})
  public void testDecodeValueSequenceWithMalformedElements()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString("foo"),
         new ASN1OctetString("foo"),
         new ASN1OctetString("foo"),
         new ASN1OctetString("foo"));

    new ChangelogEntryIntermediateResponse(new IntermediateResponse(
         ChangelogEntryIntermediateResponse.
              CHANGELOG_ENTRY_INTERMEDIATE_RESPONSE_OID,
         new ASN1OctetString(valueSequence.encode())));
  }
}
