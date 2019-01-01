/*
 * Copyright 2010-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2010-2019 Ping Identity Corporation
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



import java.util.UUID;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.ChangeLogEntry;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.Base64;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the
 * {@code DefaultChangelogEntryListener} class.
 */
public final class DefaultChangelogEntryListenerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the {@code handleChangelogEntry} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandleChangelogEntry()
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


    final GetChangelogBatchExtendedRequest r =
         new GetChangelogBatchExtendedRequest(new EndOfChangelogStartingPoint(),
              100, 300000L);

    final DefaultChangelogEntryListener l =
         new DefaultChangelogEntryListener(r);

    l.handleChangelogEntry(ir);

    assertNotNull(l.getEntryList());
    assertFalse(l.getEntryList().isEmpty());
    assertEquals(l.getEntryList().size(), 1);
  }



  /**
   * Provides test coverage for the {@code handleMissingChangelogEntries}
   * method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandleMissingChangelogEntries()
         throws Exception
  {
    final GetChangelogBatchExtendedRequest r =
         new GetChangelogBatchExtendedRequest(new EndOfChangelogStartingPoint(),
              100, 300000L);

    final DefaultChangelogEntryListener l =
         new DefaultChangelogEntryListener(r);

    final MissingChangelogEntriesIntermediateResponse ir =
         new MissingChangelogEntriesIntermediateResponse("foo");

    l.handleMissingChangelogEntries(ir);

    assertNotNull(l.getEntryList());
    assertTrue(l.getEntryList().isEmpty());
  }



  /**
   * Provides test coverage for the {@code handleOtherIntermediateResponse}
   * method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandleOtherIntermediateResponse()
         throws Exception
  {
    final GetChangelogBatchExtendedRequest r =
         new GetChangelogBatchExtendedRequest(new EndOfChangelogStartingPoint(),
              100, 300000L);

    final DefaultChangelogEntryListener l =
         new DefaultChangelogEntryListener(r);

    l.handleOtherIntermediateResponse(
         new IntermediateResponse("1.2.3.4", null));

    assertNotNull(l.getEntryList());
    assertTrue(l.getEntryList().isEmpty());
  }
}
