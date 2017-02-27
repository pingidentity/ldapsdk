/*
 * Copyright 2011-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2017 UnboundID Corp.
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
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for general change selection criteria
 * methods.
 */
public final class ChangelogBatchChangeSelectionCriteriaTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when trying to decode an ASN.1 element that doesn't
   * contain a valid changelog batch change selection criteria outer element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testMalformedOuter()
         throws Exception
  {
    ChangelogBatchChangeSelectionCriteria.decode(new ASN1OctetString("foo"));
  }



  /**
   * Tests the behavior when trying to decode an ASN.1 element that doesn't
   * contain a valid changelog batch change selection criteria inner element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testMalformedInner()
         throws Exception
  {
    ChangelogBatchChangeSelectionCriteria.decode(
         new ASN1Sequence((byte) 0xA7, new ASN1OctetString("foo")));
  }
}
