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
import java.util.EnumSet;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.TestIntermediateResponseListener;



/**
 * This class provides a set of test cases for the
 * {@code GetChangelogBatchExtendedRequest} class.
 */
public final class GetChangelogBatchExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the constructor which may be used to create an
   * instance of this extended request using a basic set of information and
   * doesn't take an entry listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicConstructorWithoutListener()
         throws Exception
  {
    GetChangelogBatchExtendedRequest r = new GetChangelogBatchExtendedRequest(
         new BeginningOfChangelogStartingPoint(), 100, 300000L);

    assertNull(r.getEntryListener());

    r = new GetChangelogBatchExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getStartingPoint());
    assertTrue(
         r.getStartingPoint() instanceof BeginningOfChangelogStartingPoint);

    assertEquals(r.getMaxChanges(), 100);

    assertEquals(r.getMaxWaitTimeMillis(), 300000L);

    assertFalse(r.waitForMaxChanges());

    assertNotNull(r.getIncludeBaseDNs());
    assertTrue(r.getIncludeBaseDNs().isEmpty());

    assertNotNull(r.getExcludeBaseDNs());
    assertTrue(r.getExcludeBaseDNs().isEmpty());

    assertNotNull(r.getChangeTypes());
    assertEquals(r.getChangeTypes(), EnumSet.allOf(ChangeType.class));

    assertFalse(r.continueOnMissingChanges());

    assertNull(r.getPareEntriesForUserDN());

    assertNull(r.getChangeSelectionCriteria());

    assertFalse(r.includeSoftDeletedEntryMods());

    assertFalse(r.includeSoftDeletedEntryDeletes());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for the constructor which may be used to create an
   * instance of this extended request using a basic set of information and
   * takes an entry listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicConstructorWithListener()
         throws Exception
  {
    GetChangelogBatchExtendedRequest r = new GetChangelogBatchExtendedRequest(
         new TestChangelogEntryListener(), new EndOfChangelogStartingPoint(), 0,
         60000L);

    assertNotNull(r.getEntryListener());
    assertTrue(r.getEntryListener() instanceof TestChangelogEntryListener);

    r = new GetChangelogBatchExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getStartingPoint());
    assertTrue(r.getStartingPoint() instanceof EndOfChangelogStartingPoint);

    assertEquals(r.getMaxChanges(), 0);

    assertEquals(r.getMaxWaitTimeMillis(), 60000L);

    assertFalse(r.waitForMaxChanges());

    assertNotNull(r.getIncludeBaseDNs());
    assertTrue(r.getIncludeBaseDNs().isEmpty());

    assertNotNull(r.getExcludeBaseDNs());
    assertTrue(r.getExcludeBaseDNs().isEmpty());

    assertNotNull(r.getChangeTypes());
    assertEquals(r.getChangeTypes(), EnumSet.allOf(ChangeType.class));

    assertFalse(r.continueOnMissingChanges());

    assertNull(r.getPareEntriesForUserDN());

    assertNull(r.getChangeSelectionCriteria());

    assertFalse(r.includeSoftDeletedEntryMods());

    assertFalse(r.includeSoftDeletedEntryDeletes());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for the constructor which may be used to create an
   * instance of this extended request using a full set of information and
   * doesn't take an entry listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testManyConstructorWithoutListener()
         throws Exception
  {
    final List<String> includeBases = Arrays.asList(
         "dc=example,dc=com",
         "o=example.com");

    final List<String> excludeBases = Arrays.asList(
         "ou=People,dc=example,dc=com",
         "ou=Groups,ec=example,dc=com");

    final EnumSet<ChangeType> changeTypes = EnumSet.of(ChangeType.MODIFY);

    GetChangelogBatchExtendedRequest r = new GetChangelogBatchExtendedRequest(
         new EndOfChangelogStartingPoint(), -1, 0L, false, includeBases,
         excludeBases, changeTypes, true, new Control("1.2.3.4"),
         new Control("5.6.7.8"));

    assertNull(r.getEntryListener());

    r = new GetChangelogBatchExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getStartingPoint());
    assertTrue(r.getStartingPoint() instanceof EndOfChangelogStartingPoint);

    assertEquals(r.getMaxChanges(), 0);

    assertEquals(r.getMaxWaitTimeMillis(), 0L);

    assertFalse(r.waitForMaxChanges());

    assertNotNull(r.getIncludeBaseDNs());
    assertEquals(r.getIncludeBaseDNs(), includeBases);

    assertNotNull(r.getExcludeBaseDNs());
    assertEquals(r.getExcludeBaseDNs(), excludeBases);

    assertNotNull(r.getChangeTypes());
    assertEquals(r.getChangeTypes(), changeTypes);

    assertTrue(r.continueOnMissingChanges());

    assertNull(r.getPareEntriesForUserDN());

    assertNull(r.getChangeSelectionCriteria());

    assertFalse(r.includeSoftDeletedEntryMods());

    assertFalse(r.includeSoftDeletedEntryDeletes());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for the constructor which may be used to create an
   * instance of this extended request using a full set of information and takes
   * an entry listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testManyConstructorWithListener()
         throws Exception
  {
    final List<String> includeBases = Arrays.asList(
         "dc=example,dc=com");

    final List<String> excludeBases = Arrays.asList(
         "ou=People,dc=example,dc=com");

    final EnumSet<ChangeType> changeTypes =
         EnumSet.of(ChangeType.ADD, ChangeType.DELETE, ChangeType.MODIFY_DN);

    GetChangelogBatchExtendedRequest r = new GetChangelogBatchExtendedRequest(
         new TestChangelogEntryListener(), new EndOfChangelogStartingPoint(),
         -1, -1L, true, includeBases, excludeBases, changeTypes, false,
         new Control("1.2.3.4"));

    assertNotNull(r.getEntryListener());
    assertTrue(r.getEntryListener() instanceof TestChangelogEntryListener);

    r = new GetChangelogBatchExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getStartingPoint());
    assertTrue(r.getStartingPoint() instanceof EndOfChangelogStartingPoint);

    assertEquals(r.getMaxChanges(), 0);

    assertEquals(r.getMaxWaitTimeMillis(), 0L);

    assertTrue(r.waitForMaxChanges());

    assertNotNull(r.getIncludeBaseDNs());
    assertEquals(r.getIncludeBaseDNs(), includeBases);

    assertNotNull(r.getExcludeBaseDNs());
    assertEquals(r.getExcludeBaseDNs(), excludeBases);

    assertNotNull(r.getChangeTypes());
    assertEquals(r.getChangeTypes(), changeTypes);

    assertFalse(r.continueOnMissingChanges());

    assertNull(r.getPareEntriesForUserDN());

    assertNull(r.getChangeSelectionCriteria());

    assertFalse(r.includeSoftDeletedEntryMods());

    assertFalse(r.includeSoftDeletedEntryDeletes());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for the constructor which may be used to create an
   * instance of this extended request using a full set of information and
   * doesn't take an entry listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMostConstructorWithoutListener()
         throws Exception
  {
    final List<String> includeBases = Arrays.asList(
         "dc=example,dc=com",
         "o=example.com");

    final List<String> excludeBases = Arrays.asList(
         "ou=People,dc=example,dc=com",
         "ou=Groups,ec=example,dc=com");

    final EnumSet<ChangeType> changeTypes = EnumSet.of(ChangeType.MODIFY);

    GetChangelogBatchExtendedRequest r = new GetChangelogBatchExtendedRequest(
         null, new EndOfChangelogStartingPoint(), -1, 0L, false, includeBases,
         excludeBases, changeTypes, true, new Control("1.2.3.4"),
         new Control("5.6.7.8"));

    assertNull(r.getEntryListener());

    r = new GetChangelogBatchExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getStartingPoint());
    assertTrue(r.getStartingPoint() instanceof EndOfChangelogStartingPoint);

    assertEquals(r.getMaxChanges(), 0);

    assertEquals(r.getMaxWaitTimeMillis(), 0L);

    assertFalse(r.waitForMaxChanges());

    assertNotNull(r.getIncludeBaseDNs());
    assertEquals(r.getIncludeBaseDNs(), includeBases);

    assertNotNull(r.getExcludeBaseDNs());
    assertEquals(r.getExcludeBaseDNs(), excludeBases);

    assertNotNull(r.getChangeTypes());
    assertEquals(r.getChangeTypes(), changeTypes);

    assertTrue(r.continueOnMissingChanges());

    assertNull(r.getPareEntriesForUserDN());

    assertNull(r.getChangeSelectionCriteria());

    assertFalse(r.includeSoftDeletedEntryMods());

    assertFalse(r.includeSoftDeletedEntryDeletes());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for the constructor which may be used to create an
   * instance of this extended request using a full set of information and takes
   * an entry listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMostConstructorWithListener()
         throws Exception
  {
    final List<String> includeBases = Arrays.asList(
         "dc=example,dc=com");

    final List<String> excludeBases = Arrays.asList(
         "ou=People,dc=example,dc=com");

    final EnumSet<ChangeType> changeTypes =
         EnumSet.of(ChangeType.ADD, ChangeType.DELETE, ChangeType.MODIFY_DN);

    GetChangelogBatchExtendedRequest r = new GetChangelogBatchExtendedRequest(
         new TestChangelogEntryListener(), new EndOfChangelogStartingPoint(),
         -1, -1L, true, includeBases, excludeBases, changeTypes, false,
         "uid=test.user,ou=People,dc=example,dc=com",
         new IgnoreAttributesChangeSelectionCriteria(true),
         new Control("1.2.3.4"));

    assertNotNull(r.getEntryListener());
    assertTrue(r.getEntryListener() instanceof TestChangelogEntryListener);

    r = new GetChangelogBatchExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getStartingPoint());
    assertTrue(r.getStartingPoint() instanceof EndOfChangelogStartingPoint);

    assertEquals(r.getMaxChanges(), 0);

    assertEquals(r.getMaxWaitTimeMillis(), 0L);

    assertTrue(r.waitForMaxChanges());

    assertNotNull(r.getIncludeBaseDNs());
    assertEquals(r.getIncludeBaseDNs(), includeBases);

    assertNotNull(r.getExcludeBaseDNs());
    assertEquals(r.getExcludeBaseDNs(), excludeBases);

    assertNotNull(r.getChangeTypes());
    assertEquals(r.getChangeTypes(), changeTypes);

    assertFalse(r.continueOnMissingChanges());

    assertNotNull(r.getPareEntriesForUserDN());
    assertEquals(new DN(r.getPareEntriesForUserDN()),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));

    assertNotNull(r.getChangeSelectionCriteria());

    assertFalse(r.includeSoftDeletedEntryMods());

    assertFalse(r.includeSoftDeletedEntryDeletes());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for the constructor which may be used to create an
   * instance of this extended request using a full set of information and a
   * {@code null} entry listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFullConstructorWithoutListener()
         throws Exception
  {
    final List<String> includeBases = Arrays.asList(
         "dc=example,dc=com");

    final List<String> excludeBases = Arrays.asList(
         "ou=People,dc=example,dc=com");

    final EnumSet<ChangeType> changeTypes =
         EnumSet.of(ChangeType.ADD, ChangeType.DELETE, ChangeType.MODIFY_DN);

    GetChangelogBatchExtendedRequest r = new GetChangelogBatchExtendedRequest(
         null, new EndOfChangelogStartingPoint(), -1, -1L, true, includeBases,
         excludeBases, changeTypes, false,
         "uid=test.user,ou=People,dc=example,dc=com",
         new IgnoreAttributesChangeSelectionCriteria(true), true, false,
         new Control("1.2.3.4"));

    assertNull(r.getEntryListener());

    r = new GetChangelogBatchExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getStartingPoint());
    assertTrue(r.getStartingPoint() instanceof EndOfChangelogStartingPoint);

    assertEquals(r.getMaxChanges(), 0);

    assertEquals(r.getMaxWaitTimeMillis(), 0L);

    assertTrue(r.waitForMaxChanges());

    assertNotNull(r.getIncludeBaseDNs());
    assertEquals(r.getIncludeBaseDNs(), includeBases);

    assertNotNull(r.getExcludeBaseDNs());
    assertEquals(r.getExcludeBaseDNs(), excludeBases);

    assertNotNull(r.getChangeTypes());
    assertEquals(r.getChangeTypes(), changeTypes);

    assertFalse(r.continueOnMissingChanges());

    assertNotNull(r.getPareEntriesForUserDN());
    assertEquals(new DN(r.getPareEntriesForUserDN()),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));

    assertNotNull(r.getChangeSelectionCriteria());

    assertTrue(r.includeSoftDeletedEntryMods());

    assertFalse(r.includeSoftDeletedEntryDeletes());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for the constructor which may be used to create an
   * instance of this extended request using a full set of information and a
   * non-{@code null} entry listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFullConstructorWithListener()
         throws Exception
  {
    final List<String> includeBases = Arrays.asList(
         "dc=example,dc=com");

    final List<String> excludeBases = Arrays.asList(
         "ou=People,dc=example,dc=com");

    final EnumSet<ChangeType> changeTypes =
         EnumSet.of(ChangeType.ADD, ChangeType.DELETE, ChangeType.MODIFY_DN);

    GetChangelogBatchExtendedRequest r = new GetChangelogBatchExtendedRequest(
         new TestChangelogEntryListener(), new EndOfChangelogStartingPoint(),
         -1, -1L, true, includeBases, excludeBases, changeTypes, false,
         "uid=test.user,ou=People,dc=example,dc=com",
         new IgnoreAttributesChangeSelectionCriteria(true), false, true,
         new Control("1.2.3.4"));

    assertNotNull(r.getEntryListener());
    assertTrue(r.getEntryListener() instanceof TestChangelogEntryListener);

    r = new GetChangelogBatchExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getStartingPoint());
    assertTrue(r.getStartingPoint() instanceof EndOfChangelogStartingPoint);

    assertEquals(r.getMaxChanges(), 0);

    assertEquals(r.getMaxWaitTimeMillis(), 0L);

    assertTrue(r.waitForMaxChanges());

    assertNotNull(r.getIncludeBaseDNs());
    assertEquals(r.getIncludeBaseDNs(), includeBases);

    assertNotNull(r.getExcludeBaseDNs());
    assertEquals(r.getExcludeBaseDNs(), excludeBases);

    assertNotNull(r.getChangeTypes());
    assertEquals(r.getChangeTypes(), changeTypes);

    assertFalse(r.continueOnMissingChanges());

    assertNotNull(r.getPareEntriesForUserDN());
    assertEquals(new DN(r.getPareEntriesForUserDN()),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));

    assertNotNull(r.getChangeSelectionCriteria());

    assertFalse(r.includeSoftDeletedEntryMods());

    assertTrue(r.includeSoftDeletedEntryDeletes());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for an attempt to decode an extended request without
   * a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeWithoutValue()
         throws Exception
  {
    new GetChangelogBatchExtendedRequest(new ExtendedRequest(
         GetChangelogBatchExtendedRequest.GET_CHANGELOG_BATCH_REQUEST_OID));
  }



  /**
   * Provides test coverage for an attempt to decode an extended request with a
   * value that is not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new GetChangelogBatchExtendedRequest(new ExtendedRequest(
         GetChangelogBatchExtendedRequest.GET_CHANGELOG_BATCH_REQUEST_OID,
         new ASN1OctetString("foo")));
  }



  /**
   * Provides test coverage for an attempt to decode an extended request with a
   * value sequence with too few elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceTooFewElements()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence();

    new GetChangelogBatchExtendedRequest(new ExtendedRequest(
         GetChangelogBatchExtendedRequest.GET_CHANGELOG_BATCH_REQUEST_OID,
         new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Provides test coverage for an attempt to decode an extended request with a
   * value sequence with a starting point that cannot be parsed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceMalformedStartingPoint()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString("foo"),
         new ASN1Integer(0));

    new GetChangelogBatchExtendedRequest(new ExtendedRequest(
         GetChangelogBatchExtendedRequest.GET_CHANGELOG_BATCH_REQUEST_OID,
         new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Provides test coverage for an attempt to decode an extended request with a
   * value sequence with a set of include base DNs that cannot be parsed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceMalformedIncludeList()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new EndOfChangelogStartingPoint().encode(),
         new ASN1OctetString("foo"),
         new ASN1OctetString((byte) 0xA2, "bar"));

    new GetChangelogBatchExtendedRequest(new ExtendedRequest(
         GetChangelogBatchExtendedRequest.GET_CHANGELOG_BATCH_REQUEST_OID,
         new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Provides test coverage for an attempt to decode an extended request with a
   * value sequence with an element with an invalid type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceInvalidElementType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new EndOfChangelogStartingPoint().encode(),
         new ASN1Integer(0),
         new ASN1Integer((byte) 0x80, -1),
         new ASN1OctetString((byte) 0x00, "foo"));

    new GetChangelogBatchExtendedRequest(new ExtendedRequest(
         GetChangelogBatchExtendedRequest.GET_CHANGELOG_BATCH_REQUEST_OID,
         new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Provides test coverage for an attempt to decode an extended request with a
   * value sequence with an invalid change type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceInvalidChangeType()
         throws Exception
  {
    final ASN1Set changeTypeSet = new ASN1Set((byte) 0xA4,
         new ASN1Enumerated(0),
         new ASN1Enumerated(5));

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new EndOfChangelogStartingPoint().encode(),
         new ASN1Integer(0),
         changeTypeSet);

    new GetChangelogBatchExtendedRequest(new ExtendedRequest(
         GetChangelogBatchExtendedRequest.GET_CHANGELOG_BATCH_REQUEST_OID,
         new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Provides test coverage for an attempt to send a request to the server and
   * retrieve a result for a case in which no entry listener is in use.  In this
   * case, we don't care about the result because the server may not support
   * this request.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWithoutListener()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection conn = getAdminConnection();

    final GetChangelogBatchExtendedRequest request =
         new GetChangelogBatchExtendedRequest(new EndOfChangelogStartingPoint(),
              0, 0L);

    try
    {
      final ExtendedResult result = conn.processExtendedOperation(request);
      assertTrue(result instanceof GetChangelogBatchExtendedResult);
    }
    catch (final LDAPException le)
    {
      // We don't really care about this.
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Provides test coverage for an attempt to send a request to the server and
   * retrieve a result for a case in which an entry listener is in use.  In this
   * case, we don't care about the result because the server may not support
   * this request.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWithListener()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection conn = getAdminConnection();

    final GetChangelogBatchExtendedRequest request =
         new GetChangelogBatchExtendedRequest(new TestChangelogEntryListener(),
              new EndOfChangelogStartingPoint(), 0, 0L);

    try
    {
      final ExtendedResult result = conn.processExtendedOperation(request);
      assertTrue(result instanceof GetChangelogBatchExtendedResult);
    }
    catch (final LDAPException le)
    {
      // We don't really care about this.
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Provides test coverage for an attempt to send a request to the server over
   * a connection that is not established.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWhileNotEstablished()
         throws Exception
  {
    final LDAPConnection conn = new LDAPConnection();

    final GetChangelogBatchExtendedRequest request =
         new GetChangelogBatchExtendedRequest(new EndOfChangelogStartingPoint(),
              0, 0L);

    try
    {
      conn.processExtendedOperation(request);
      fail("Expected an exception when trying to send a request over a " +
           "connection that is not established.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for an attempt to send a request to the server and
   * retrieve a result for a case in which no entry listener is in use but the
   * request has a custom intermediate response listener.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWithAlternateIntermediateResponseListener()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection conn = getAdminConnection();

    final GetChangelogBatchExtendedRequest request =
         new GetChangelogBatchExtendedRequest(new EndOfChangelogStartingPoint(),
              0, 0L);
    request.setIntermediateResponseListener(
         new TestIntermediateResponseListener());

    try
    {
      conn.processExtendedOperation(request);
      fail("Expected an exception when trying to process a request with a " +
           "custom intermediate response listener.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
    finally
    {
      conn.close();
    }
  }
}
