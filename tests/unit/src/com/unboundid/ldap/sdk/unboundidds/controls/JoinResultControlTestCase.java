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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.LinkedList;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;



/**
 * This class provides a set of test cases for the {@code JoinResultControl}
 * class.
 */
public class JoinResultControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides a set of tests that cover the simple "success" constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessConstructor()
         throws Exception
  {
    Entry e = new Entry(
         "dn: ou=match1,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: match1");

    LinkedList<JoinedEntry> joinResults = new LinkedList<JoinedEntry>();
    joinResults.add(new JoinedEntry(e, null));

    e = new Entry(
         "dn: ou=match2,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: match2");
    joinResults.add(new JoinedEntry(e, null));

    JoinResultControl c = new JoinResultControl(joinResults);
    c = new JoinResultControl().decodeControl(c.getOID(), c.isCritical(),
         c.getValue());

    assertNotNull(c);

    assertNotNull(c.getResultCode());
    assertEquals(c.getResultCode(), ResultCode.SUCCESS);

    assertNull(c.getDiagnosticMessage());

    assertNull(c.getMatchedDN());

    assertNotNull(c.getReferralURLs());
    assertTrue(c.getReferralURLs().isEmpty());

    assertNotNull(c.getJoinResults());
    assertFalse(c.getJoinResults().isEmpty());
    assertEquals(c.getJoinResults().size(), 2);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides a set of tests that cover the full constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFullConstructor()
         throws Exception
  {
    Entry e = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    LinkedList<JoinedEntry> joinResults = new LinkedList<JoinedEntry>();
    joinResults.add(new JoinedEntry(e, null));

    LinkedList<String> referralURLs = new LinkedList<String>();
    referralURLs.add("ldap://server1.example.com:389/dc=example,dc=com");
    referralURLs.add("ldap://server2.example.com:389/dc=example,dc=com");

    JoinResultControl c = new JoinResultControl(ResultCode.NO_SUCH_OBJECT,
         "diagnosticMessage", "cn=matched,cn=dn", referralURLs, joinResults);
    c = new JoinResultControl().decodeControl(c.getOID(), c.isCritical(),
         c.getValue());

    assertNotNull(c);

    assertNotNull(c.getResultCode());
    assertEquals(c.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(c.getDiagnosticMessage());
    assertEquals(c.getDiagnosticMessage(), "diagnosticMessage");

    assertNotNull(c.getMatchedDN());
    assertEquals(new DN(c.getMatchedDN()),
                 new DN("cn=matched,cn=dn"));

    assertNotNull(c.getReferralURLs());
    assertFalse(c.getReferralURLs().isEmpty());
    assertEquals(c.getReferralURLs().size(), 2);

    assertNotNull(c.getJoinResults());
    assertFalse(c.getJoinResults().isEmpty());
    assertEquals(c.getJoinResults().size(), 1);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides a set of tests that cover the full constructor with no join
   * results.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFullConstructorNoResults()
         throws Exception
  {
    JoinResultControl c = new JoinResultControl(ResultCode.NO_SUCH_OBJECT,
         "diagnosticMessage", "cn=matched,cn=dn", null, null);
    c = new JoinResultControl().decodeControl(c.getOID(), c.isCritical(),
         c.getValue());

    assertNotNull(c);

    assertNotNull(c.getResultCode());
    assertEquals(c.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(c.getDiagnosticMessage());
    assertEquals(c.getDiagnosticMessage(), "diagnosticMessage");

    assertNotNull(c.getMatchedDN());
    assertEquals(new DN(c.getMatchedDN()),
                 new DN("cn=matched,cn=dn"));

    assertNotNull(c.getReferralURLs());
    assertTrue(c.getReferralURLs().isEmpty());

    assertNotNull(c.getJoinResults());
    assertTrue(c.getJoinResults().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to decode a control with no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    new JoinResultControl(JoinResultControl.JOIN_RESULT_OID, false, null);
  }



  /**
   * Tests the behavior when trying to decode a control whose value is not a
   * valid sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new JoinResultControl(JoinResultControl.JOIN_RESULT_OID, false,
                          new ASN1OctetString((byte) 0x00, new byte[1]));
  }



  /**
   * Tests the behavior when trying to decode a control whose value is a
   * sequence containing an invalid element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceHasInvalidElement()
         throws Exception
  {
    ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated(0),
         new ASN1OctetString(),
         new ASN1OctetString(),
         new ASN1OctetString((byte) 0xFF, "invalidType"));

    new JoinResultControl(JoinResultControl.JOIN_RESULT_OID, false,
        new ASN1OctetString(valueSequence.encode()));
  }



  /**
   * Tests the {@code get} method with an entry that does not contain a join
   * result control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMissing()
         throws Exception
  {
    final Control[] controls = new Control[0];

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);

    final JoinResultControl c = JoinResultControl.get(e);
    assertNull(c);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is already of the appropriate type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidCorrectType()
         throws Exception
  {
    final LinkedList<JoinedEntry> entryList = new LinkedList<JoinedEntry>();
    entryList.add(new JoinedEntry(generateOrgEntry("example.com", null), null));

    final Control[] controls =
    {
      new JoinResultControl(entryList)
    };

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);

    final JoinResultControl c = JoinResultControl.get(e);
    assertNotNull(c);

    assertNotNull(c.getJoinResults());
    assertEquals(c.getJoinResults().size(), 1);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that can be parsed as a join result control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidGenericType()
         throws Exception
  {
    final LinkedList<JoinedEntry> entryList = new LinkedList<JoinedEntry>();
    entryList.add(new JoinedEntry(generateOrgEntry("example.com", null), null));

    final Control tmp = new JoinResultControl(entryList);

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);

    final JoinResultControl c = JoinResultControl.get(e);
    assertNotNull(c);

    assertNotNull(c.getJoinResults());
    assertEquals(c.getJoinResults().size(), 1);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that cannot be parsed as a join result control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetInvalidGenericType()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(JoinResultControl.JOIN_RESULT_OID, false, null)
    };

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);


    JoinResultControl.get(e);
  }
}
