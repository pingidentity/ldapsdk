/*
 * Copyright 2011-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2020 Ping Identity Corporation
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
 * This class provides a set of test cases for the ignore attributes change
 * selection criteria type.
 */
public final class IgnoreAttributesChangeSelectionCriteriaTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior in which only operational attributes should be ignored.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIgnoreOnlyOperational()
         throws Exception
  {
    IgnoreAttributesChangeSelectionCriteria c =
         new IgnoreAttributesChangeSelectionCriteria(true);

    final ChangelogBatchChangeSelectionCriteria decodedCriteria =
         ChangelogBatchChangeSelectionCriteria.decode(c.encode());
    assertNotNull(decodedCriteria);
    assertTrue(decodedCriteria instanceof
         IgnoreAttributesChangeSelectionCriteria);
    c = (IgnoreAttributesChangeSelectionCriteria) decodedCriteria;

    assertTrue(c.ignoreOperationalAttributes());

    assertNotNull(c.getAttributeNames());
    assertTrue(c.getAttributeNames().isEmpty());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior in which only an explicitly-defined set of attributes
   * should be ignored.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIgnoreOnlyExplicit()
         throws Exception
  {
    IgnoreAttributesChangeSelectionCriteria c =
         new IgnoreAttributesChangeSelectionCriteria(false, "givenName", "sn");

    final ChangelogBatchChangeSelectionCriteria decodedCriteria =
         ChangelogBatchChangeSelectionCriteria.decode(c.encode());
    assertNotNull(decodedCriteria);
    assertTrue(decodedCriteria instanceof
         IgnoreAttributesChangeSelectionCriteria);
    c = (IgnoreAttributesChangeSelectionCriteria) decodedCriteria;

    assertFalse(c.ignoreOperationalAttributes());

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
    IgnoreAttributesChangeSelectionCriteria.decodeInnerElement(
         new ASN1OctetString("foo"));
  }
}
