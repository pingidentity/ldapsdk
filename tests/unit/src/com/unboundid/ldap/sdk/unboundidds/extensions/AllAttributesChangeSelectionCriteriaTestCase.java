/*
 * Copyright 2011-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2019 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the all attributes change
 * selection criteria type.
 */
public final class AllAttributesChangeSelectionCriteriaTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides general test coverage for the all attributes change selection
   * criteria object type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGeneral()
         throws Exception
  {
    AllAttributesChangeSelectionCriteria c =
         new AllAttributesChangeSelectionCriteria("givenName", "sn");

    final ChangelogBatchChangeSelectionCriteria decodedCriteria =
         ChangelogBatchChangeSelectionCriteria.decode(c.encode());
    assertNotNull(decodedCriteria);
    assertTrue(decodedCriteria instanceof AllAttributesChangeSelectionCriteria);
    c = (AllAttributesChangeSelectionCriteria) decodedCriteria;

    assertNotNull(c.getAttributeNames());
    assertFalse(c.getAttributeNames().isEmpty());
    assertEquals(c.getAttributeNames().size(), 2);
    assertTrue(c.getAttributeNames().contains("givenName"));
    assertTrue(c.getAttributeNames().contains("sn"));

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
    AllAttributesChangeSelectionCriteria.decodeInnerElement(
         new ASN1OctetString("foo"));
  }
}
