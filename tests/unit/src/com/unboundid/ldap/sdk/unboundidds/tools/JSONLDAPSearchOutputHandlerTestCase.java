/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.io.ByteArrayOutputStream;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.extensions.NoticeOfDisconnectionExtendedResult;
import com.unboundid.util.json.JSONObject;



/**
 * Provides test coverage for the JSON LDAPSearch output handler.
 */
public final class JSONLDAPSearchOutputHandlerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Verify that the {@code formatHeader} method doesn't generate any output.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFormatHeader()
         throws Exception
  {
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    final LDAPSearch ldapSearch =
         new LDAPSearch(outputStream, outputStream);

    final JSONLDAPSearchOutputHandler outputHandler =
         new JSONLDAPSearchOutputHandler(ldapSearch);

    outputHandler.formatHeader();

    assertEquals(outputStream.size(), 0);
  }



  /**
   * Tests the behavior of the {@code formatSearchResultEntry} method for an
   * entry with a DN but no attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFormatSearchResultEntryNoAttributes()
         throws Exception
  {
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    final LDAPSearch ldapSearch =
         new LDAPSearch(outputStream, outputStream);

    final JSONLDAPSearchOutputHandler outputHandler =
         new JSONLDAPSearchOutputHandler(ldapSearch);

    outputHandler.formatSearchResultEntry(new SearchResultEntry(
         new Entry("dc=example,dc=com")));

    assertValidJSONObject(outputStream);
  }



  /**
   * Tests the behavior of the {@code formatSearchResultEntry} method for an
   * entry that has attributes without values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFormatSearchResultEntryWithAttributesWithoutValues()
         throws Exception
  {
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    final LDAPSearch ldapSearch =
         new LDAPSearch(outputStream, outputStream);

    final JSONLDAPSearchOutputHandler outputHandler =
         new JSONLDAPSearchOutputHandler(ldapSearch);

    outputHandler.formatSearchResultEntry(new SearchResultEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: ",
         "dc: ")));

    assertValidJSONObject(outputStream);
  }



  /**
   * Tests the behavior of the {@code formatSearchResultEntry} method for an
   * entry that has attributes with values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFormatSearchResultEntryWithAttributesWithValues()
         throws Exception
  {
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    final LDAPSearch ldapSearch =
         new LDAPSearch(outputStream, outputStream);

    final JSONLDAPSearchOutputHandler outputHandler =
         new JSONLDAPSearchOutputHandler(ldapSearch);

    outputHandler.formatSearchResultEntry(new SearchResultEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example")));

    assertValidJSONObject(outputStream);
  }



  /**
   * Tests the behavior of the {@code formatSearchResultEntry} method for an
   * entry that has attributes with values, and that also includes controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFormatSearchResultEntryWithAttributesWithValuesAndControls()
         throws Exception
  {
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    final LDAPSearch ldapSearch =
         new LDAPSearch(outputStream, outputStream);

    final JSONLDAPSearchOutputHandler outputHandler =
         new JSONLDAPSearchOutputHandler(ldapSearch);

    outputHandler.formatSearchResultEntry(new SearchResultEntry(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"),
         new Control("1.2.3.4"),
         new Control("1.2.3.5", true, new ASN1OctetString("foo"))));

    assertValidJSONObject(outputStream);
  }



  /**
   * Tests the behavior of the {@code formatSearchResultReference} method for
   * a reference that has a single URL.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFormatSearchResultReferenceSingleURL()
         throws Exception
  {
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    final LDAPSearch ldapSearch =
         new LDAPSearch(outputStream, outputStream);

    final JSONLDAPSearchOutputHandler outputHandler =
         new JSONLDAPSearchOutputHandler(ldapSearch);

    final String[] referralURLs =
    {
      "ldap://ds.example.com:389/dc=example,dc=com"
    };

    outputHandler.formatSearchResultReference(
         new SearchResultReference(referralURLs, null));

    assertValidJSONObject(outputStream);
  }



  /**
   * Tests the behavior of the {@code formatSearchResultReference} method for
   * a reference that has multiple URLs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFormatSearchResultReferenceMultipleURLs()
         throws Exception
  {
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    final LDAPSearch ldapSearch =
         new LDAPSearch(outputStream, outputStream);

    final JSONLDAPSearchOutputHandler outputHandler =
         new JSONLDAPSearchOutputHandler(ldapSearch);

    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/dc=example,dc=com",
      "ldap://ds2.example.com:389/dc=example,dc=com"
    };

    outputHandler.formatSearchResultReference(
         new SearchResultReference(referralURLs, null));

    assertValidJSONObject(outputStream);
  }



  /**
   * Tests the behavior of the {@code formatSearchResultReference} method for
   * a reference that has multiple URLs and includes controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFormatSearchResultReferenceMultipleURLsAndControls()
         throws Exception
  {
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    final LDAPSearch ldapSearch =
         new LDAPSearch(outputStream, outputStream);

    final JSONLDAPSearchOutputHandler outputHandler =
         new JSONLDAPSearchOutputHandler(ldapSearch);

    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/dc=example,dc=com",
      "ldap://ds2.example.com:389/dc=example,dc=com"
    };

    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString("foo"))
    };

    outputHandler.formatSearchResultReference(
         new SearchResultReference(referralURLs, controls));

    assertValidJSONObject(outputStream);
  }



  /**
   * Tests the behavior of the {@code formatResult} method for an
   * {@code LDAPResult} that is not a {@code SearchResult}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFormatLDAPResult()
         throws Exception
  {
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    final LDAPSearch ldapSearch =
         new LDAPSearch(outputStream, outputStream);

    final JSONLDAPSearchOutputHandler outputHandler =
         new JSONLDAPSearchOutputHandler(ldapSearch);

    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/dc=example,dc=com",
      "ldap://ds2.example.com:389/dc=example,dc=com"
    };

    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString("foo"))
    };

    outputHandler.formatResult(new LDAPResult(1,
         ResultCode.UNWILLING_TO_PERFORM, "I don't feel like it",
         "dc=example,dc=com", referralURLs, controls));

    assertValidJSONObject(outputStream);
  }



  /**
   * Tests the behavior of the {@code formatResult} method for a
   * {@code SearchResult}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFormatSearchResult()
         throws Exception
  {
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    final LDAPSearch ldapSearch =
         new LDAPSearch(outputStream, outputStream);

    final JSONLDAPSearchOutputHandler outputHandler =
         new JSONLDAPSearchOutputHandler(ldapSearch);

    outputHandler.formatResult(new SearchResult(2, ResultCode.SUCCESS, null,
         null, null, 123, 456, null));

    assertValidJSONObject(outputStream);
  }



  /**
   * Tests the behavior of the {@code formatUnsolicitedNotification} method with
   * a notification that does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFormatUnsolicitedNotificationWithoutValue()
         throws Exception
  {
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    final LDAPSearch ldapSearch =
         new LDAPSearch(outputStream, outputStream);

    final JSONLDAPSearchOutputHandler outputHandler =
         new JSONLDAPSearchOutputHandler(ldapSearch);

    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/dc=example,dc=com",
      "ldap://ds2.example.com:389/dc=example,dc=com"
    };

    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString("foo"))
    };

    outputHandler.formatUnsolicitedNotification(null,
         new NoticeOfDisconnectionExtendedResult(0, ResultCode.OTHER,
              "Connection terminated", "dc=example,dc=com", referralURLs,
              controls));

    assertValidJSONObject(outputStream);
  }



  /**
   * Tests the behavior of the {@code formatUnsolicitedNotification} method with
   * a notification that does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFormatUnsolicitedNotificationWithValue()
         throws Exception
  {
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    final LDAPSearch ldapSearch =
         new LDAPSearch(outputStream, outputStream);

    final JSONLDAPSearchOutputHandler outputHandler =
         new JSONLDAPSearchOutputHandler(ldapSearch);

    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/dc=example,dc=com",
      "ldap://ds2.example.com:389/dc=example,dc=com"
    };

    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString("foo"))
    };

    outputHandler.formatUnsolicitedNotification(null,
         new ExtendedResult(0, ResultCode.OTHER, "Diagnostic Message",
              "o=Matched DN", referralURLs, "1.2.3.3",
              new ASN1OctetString("bar"), controls));

    assertValidJSONObject(outputStream);
  }



  /**
   * Ensures that the provided byte array output stream contains a valid JSON
   * object.
   *
   * @param  os  The byte array output stream containing the data to verify.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void assertValidJSONObject(final ByteArrayOutputStream os)
          throws  Exception
  {
    new JSONObject(new String(os.toByteArray(), "UTF-8"));
  }
}
