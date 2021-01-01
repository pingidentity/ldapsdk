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



import java.io.ByteArrayInputStream;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the SearchResultReference class.
 */
public class SearchResultReferenceTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   */
  @Test()
  public void testConstructor1()
  {
    String[] referralURLs =
    {
      "ldap://test1.example.com/dc=example,dc=com",
      "ldap://test2.example.com/dc=example,dc=com",
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultReference ref =
         new SearchResultReference(referralURLs, controls);

    assertNotNull(ref.getReferralURLs());
    assertEquals(ref.getReferralURLs().length, 2);

    assertNotNull(ref.getControls());
    assertEquals(ref.getControls().length, 2);

    assertNotNull(ref.getControl("1.2.3.4"));
    assertNotNull(ref.getControl("1.2.3.5"));
    assertNull(ref.getControl("1.2.3.6"));

    ref.getMessageID();

    assertNotNull(ref.toString());
  }



  /**
   * Tests the first constructor with a {@code null} set of controls.
   */
  @Test()
  public void testConstructor1NullControls()
  {
    String[] referralURLs =
    {
      "ldap://test1.example.com/dc=example,dc=com",
      "ldap://test2.example.com/dc=example,dc=com",
    };

    Control[] controls = null;

    SearchResultReference ref =
         new SearchResultReference(referralURLs, controls);

    assertNotNull(ref.getReferralURLs());
    assertEquals(ref.getReferralURLs().length, 2);

    assertNotNull(ref.getControls());
    assertEquals(ref.getControls().length, 0);

    ref.getMessageID();

    assertNotNull(ref.toString());
  }



  /**
   * Tests the first constructor with {@code null} elements.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1Null()
  {
    new SearchResultReference(null, null);
  }



  /**
   * Creates a smart referral entry, verifies that searching the directory will
   * return a search result reference, and then deletes that entry using the
   * ManageDsaIT control.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchWithReferral()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    String dn = "ou=Test Referral," + getTestBaseDN();
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "referral", "extensibleObject"),
      new Attribute("ou", "Test Referral"),
      new Attribute("ref", "ldap://test1.example.com/" + dn,
                    "ldap://test2.example.com/" + dn)
    };

    conn.add(dn, attrs);

    SearchResult searchResult = conn.search(getTestBaseDN(), SearchScope.SUB,
                                            "(objectClass=*)");
    assertEquals(searchResult.getReferenceCount(), 1);

    try
    {
      conn.delete(dn);
      fail("Expected an exception when trying to delete a referral entry " +
           "without the ManageDsaIT control.");
    }
    catch (LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.REFERRAL);
    }

    Control[] controls =
    {
      new ManageDsaITRequestControl()
    };

    conn.delete(new DeleteRequest(dn, controls));
    conn.delete(getTestBaseDN());
    conn.close();
  }



  /**
   * Tests the {@code readSearchReferenceFrom} method with an element in which
   * the protocol op is not a valid sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadSearchReferenceProtocolOpNotSequence()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();

    ASN1BufferSequence msgSequence = b.beginSequence();
    b.addInteger(1);
    b.addInteger(LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_REFERENCE, 1);
    msgSequence.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    LDAPMessage.readLDAPResponseFrom(reader, true);
  }



  /**
   * Tests the {@code readSearchReferenceFrom} method with an element containing
   * a malformed control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadSearchReferenceMalformedControl()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();

    ASN1BufferSequence msgSequence = b.beginSequence();
    b.addInteger(1);

    ASN1BufferSequence opSequence =
         b.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_REFERENCE);
    b.addOctetString("ldap://server.example.com/dc=example,dc=com");
    opSequence.end();

    ASN1BufferSequence ctrlsSequence =
         b.beginSequence(LDAPMessage.MESSAGE_TYPE_CONTROLS);
    ASN1BufferSequence ctlSequence = b.beginSequence();
    b.addOctetString("1.2.3.4");
    b.addInteger(1);
    ctlSequence.end();
    ctrlsSequence.end();

    msgSequence.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    LDAPMessage.readLDAPResponseFrom(reader, true);
  }
}
