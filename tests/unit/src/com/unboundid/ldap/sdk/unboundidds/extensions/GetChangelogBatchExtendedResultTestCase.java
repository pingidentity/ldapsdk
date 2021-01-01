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
import java.util.List;
import java.util.UUID;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.ChangeLogEntry;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the
 * {@code GetChangelogBatchExtendedResult} class.
 */
public final class GetChangelogBatchExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the constructor intended for use when creating an error result with
   * no encoded value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenericResult()
         throws Exception
  {
    final String[] referralURLs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server2.example.com/dc=example,dc=com"
    };

    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("5.6.7.8"),
    };

    GetChangelogBatchExtendedResult r = new GetChangelogBatchExtendedResult(
         new LDAPResult(1, ResultCode.OTHER, "diagnosticMessage",
              "dc=example,dc=com", referralURLs, controls));
    r = new GetChangelogBatchExtendedResult(r, -1);

    assertFalse(r.hasValue());
    assertNull(r.getValue());

    assertNull(r.getResumeToken());

    assertFalse(r.moreChangesAvailable());

    assertFalse(r.changesAlreadyPurged());

    assertNull(r.getAdditionalInfo());

    assertEquals(r.getEntryCount(), -1);

    assertNull(r.getChangelogEntries());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the constructor intended for use on the server side to create an
   * extended result from the components of the result.  The result will
   * represent an error condition and no value should be generated.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testServerSideConstructorWithErrorResult()
         throws Exception
  {
    final String[] referralURLs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server2.example.com/dc=example,dc=com"
    };

    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("5.6.7.8"),
    };

    GetChangelogBatchExtendedResult r = new GetChangelogBatchExtendedResult(
         new LDAPResult(1, ResultCode.OTHER, "diagnosticMessage",
              "dc=example,dc=com", referralURLs, controls),
         -1, null, false, -123, false, null);
    r = new GetChangelogBatchExtendedResult(r, -1);

    assertTrue(r.hasValue());
    assertNotNull(r.getValue());

    assertNull(r.getResumeToken());

    assertFalse(r.moreChangesAvailable());

    assertEquals(r.getEstimatedChangesRemaining(), -1);

    assertFalse(r.changesAlreadyPurged());

    assertNull(r.getAdditionalInfo());

    assertEquals(r.getEntryCount(), -1);

    assertNull(r.getChangelogEntries());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the constructor intended for use on the server side to create an
   * extended result from the components of the result.  The result will
   * represent an error condition and no value should be generated.  However, an
   * entry list will be provided that makes it possible to get a resume token.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testServerSideConstructorWithErrorResultAndEntryList()
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

    final ChangelogEntryIntermediateResponse ir =
         new ChangelogEntryIntermediateResponse(e, serverID, resumeToken,
              new Control("1.2.3.4"), new Control("5.6.7.8"));

    final List<ChangelogEntryIntermediateResponse> entryList =
         Arrays.asList(ir);
    GetChangelogBatchExtendedResult r = new GetChangelogBatchExtendedResult(
         new LDAPResult(1, ResultCode.OTHER));
    r = new GetChangelogBatchExtendedResult(r, entryList);

    assertFalse(r.hasValue());
    assertNull(r.getValue());

    assertNotNull(r.getResumeToken());
    assertTrue(Arrays.equals(r.getResumeToken().getValue(),
         new ASN1OctetString("foo").getValue()));

    assertFalse(r.moreChangesAvailable());

    assertFalse(r.changesAlreadyPurged());

    assertNull(r.getAdditionalInfo());

    assertEquals(r.getEntryCount(), 1);

    assertNotNull(r.getChangelogEntries());
    assertEquals(r.getChangelogEntries(), entryList);

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the constructor intended for use on the server side to create an
   * extended result from the components of the result.  All elements of the
   * result will be provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testServerSideConstructorWithAllElements()
         throws Exception
  {
    GetChangelogBatchExtendedResult r = new GetChangelogBatchExtendedResult(
         new LDAPResult(1, ResultCode.SUCCESS), 10, new ASN1OctetString("foo"),
         true, 123, true, "bar");
    r = new GetChangelogBatchExtendedResult(r, 10);

    assertTrue(r.hasValue());
    assertNotNull(r.getValue());

    assertNotNull(r.getResumeToken());
    assertTrue(Arrays.equals(r.getResumeToken().getValue(),
         new ASN1OctetString("foo").getValue()));

    assertTrue(r.moreChangesAvailable());

    assertEquals(r.getEstimatedChangesRemaining(), 123);

    assertTrue(r.changesAlreadyPurged());

    assertNotNull(r.getAdditionalInfo());
    assertEquals(r.getAdditionalInfo(), "bar");

    assertEquals(r.getEntryCount(), 10);

    assertNull(r.getChangelogEntries());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the constructor intended for use on the server side to create an
   * extended result from the components of the result.  All elements of the
   * result will be provided, as well as an entry list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testServerSideConstructorWithAllElementsAndEntryList()
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

    final ChangelogEntryIntermediateResponse ir =
         new ChangelogEntryIntermediateResponse(e, serverID, resumeToken,
              new Control("1.2.3.4"), new Control("5.6.7.8"));

    final List<ChangelogEntryIntermediateResponse> entryList =
         Arrays.asList(ir);

    GetChangelogBatchExtendedResult r = new GetChangelogBatchExtendedResult(
         new LDAPResult(1, ResultCode.SUCCESS), 1, new ASN1OctetString("foo"),
         true, true, "bar");
    r = new GetChangelogBatchExtendedResult(r, entryList);

    assertTrue(r.hasValue());
    assertNotNull(r.getValue());

    assertNotNull(r.getResumeToken());
    assertTrue(Arrays.equals(r.getResumeToken().getValue(),
         new ASN1OctetString("foo").getValue()));

    assertTrue(r.moreChangesAvailable());

    assertEquals(r.getEstimatedChangesRemaining(), -1);

    assertTrue(r.changesAlreadyPurged());

    assertNotNull(r.getAdditionalInfo());
    assertEquals(r.getAdditionalInfo(), "bar");

    assertEquals(r.getEntryCount(), 1);

    assertNotNull(r.getChangelogEntries());
    assertEquals(r.getChangelogEntries(), entryList);

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when attempting to decode an instance of the extended
   * result with a value that cannot be parsed as a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new GetChangelogBatchExtendedResult(new ExtendedResult(1,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString("foo"), null), -1);
  }



  /**
   * Tests the behavior when attempting to decode an instance of the extended
   * result with a value sequence with an invalid element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidValueSequenceType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x00, "foo"));

    new GetChangelogBatchExtendedResult(new ExtendedResult(1,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(valueSequence.encode()), null), -1);
  }



  /**
   * Tests the behavior when attempting to decode an instance of the extended
   * result with a value sequence with a malformed moreChangesAvailable element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedMoreChangesAvailable()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x81, "foo"));

    new GetChangelogBatchExtendedResult(new ExtendedResult(1,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(valueSequence.encode()), null), -1);
  }



  /**
   * Tests the behavior when attempting to decode an instance of the extended
   * result with a value sequence that is missing a resume token.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeMissingResumeToken()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Boolean((byte) 0x81, true));


    final GetChangelogBatchExtendedResult r =
         new GetChangelogBatchExtendedResult(new ExtendedResult(1,
              ResultCode.SUCCESS, null, null, null, null,
              new ASN1OctetString(valueSequence.encode()), null), -1);


    assertTrue(r.hasValue());
    assertNotNull(r.getValue());

    assertNull(r.getResumeToken());

    assertTrue(r.moreChangesAvailable());

    assertFalse(r.changesAlreadyPurged());

    assertNull(r.getAdditionalInfo());

    assertEquals(r.getEntryCount(), -1);

    assertNull(r.getChangelogEntries());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when attempting to decode an instance of the extended
   * result with a value sequence that is missing a more changes available
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMissingMoreChangesAvailable()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "foo"));


    new GetChangelogBatchExtendedResult(new ExtendedResult(1,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(valueSequence.encode()), null), -1);
  }
}
