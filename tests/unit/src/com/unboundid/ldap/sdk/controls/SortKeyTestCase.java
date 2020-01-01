/*
 * Copyright 2007-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2007-2020 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.controls;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the SortKey class.
 */
public class SortKeyTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    SortKey sortKey = new SortKey("cn");
    sortKey = SortKey.decode(sortKey.encode());

    assertEquals(sortKey.getAttributeName(), "cn");

    assertFalse(sortKey.reverseOrder());

    assertNull(sortKey.getMatchingRuleID());

    assertNotNull(sortKey.encode());

    assertNotNull(sortKey.toString());
  }



  /**
   * Tests the second constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    SortKey sortKey = new SortKey("cn", true);
    sortKey = SortKey.decode(sortKey.encode());

    assertEquals(sortKey.getAttributeName(), "cn");

    assertTrue(sortKey.reverseOrder());

    assertNull(sortKey.getMatchingRuleID());

    assertNotNull(sortKey.encode());

    assertNotNull(sortKey.toString());
  }



  /**
   * Tests the third constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    SortKey sortKey = new SortKey("cn", "1.2.3.4", true);
    sortKey = SortKey.decode(sortKey.encode());

    assertEquals(sortKey.getAttributeName(), "cn");

    assertTrue(sortKey.reverseOrder());

    assertNotNull(sortKey.getMatchingRuleID());
    assertEquals(sortKey.getMatchingRuleID(), "1.2.3.4");

    assertNotNull(sortKey.encode());

    assertNotNull(sortKey.toString());
  }



  /**
   * Tests the {@code decode} method with an element that is not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNotSequence()
         throws Exception
  {
    SortKey.decode(new ASN1OctetString("foo"));
  }



  /**
   * Tests the {@code decode} method with a sequence with an invalid number of
   * elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeEmptySequence()
         throws Exception
  {
    SortKey.decode(new ASN1Sequence());
  }



  /**
   * Tests the {@code decode} method with a sequence that contains an element
   * with an invalid type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSequenceElementWithInvalidType()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1OctetString("foo"),
      new ASN1OctetString("bar")
    };

    SortKey.decode(new ASN1Sequence(elements));
  }



  /**
   * Tests the {@code decode} method in which the reverse order element is not
   * a Boolean.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSequenceReverseOrderNotBoolean()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1OctetString("foo"),
      new ASN1OctetString((byte) 0x81, "bar")
    };

    SortKey.decode(new ASN1Sequence(elements));
  }
}
