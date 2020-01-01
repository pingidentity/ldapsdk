/*
 * Copyright 2014-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2020 Ping Identity Corporation
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



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the notification destination
 * change selection criteria type.
 */
public final class NotificationDestinationChangeSelectionCriteriaTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides general test coverage for the notification destination change
   * selection criteria object type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGeneral()
         throws Exception
  {
    NotificationDestinationChangeSelectionCriteria c =
         new NotificationDestinationChangeSelectionCriteria("foo");

    final ASN1Element encoded = c.encode();
    assertEquals(encoded.encode(),
         new byte[] { (byte) 0xA7, 0x05, (byte) 0x84, 0x03, 0x66, 0x6F, 0x6F });

    final ChangelogBatchChangeSelectionCriteria decodedCriteria =
         ChangelogBatchChangeSelectionCriteria.decode(encoded);
    assertNotNull(decodedCriteria);
    assertTrue(decodedCriteria instanceof
         NotificationDestinationChangeSelectionCriteria);
    c = (NotificationDestinationChangeSelectionCriteria) decodedCriteria;

    assertNotNull(c.getDestinationEntryUUID());
    assertEquals(c.getDestinationEntryUUID(), "foo");

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to decode a malformed inner element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedInnerElement()
         throws Exception
  {
    NotificationDestinationChangeSelectionCriteria.decodeInnerElement(null);
  }
}
