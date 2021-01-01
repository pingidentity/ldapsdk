/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the changelog entry attribute exceeded
 * max values count object.
 */
public final class ChangeLogEntryAttributeExceededMaxValuesCountTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for a valid value string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidValueString()
         throws Exception
  {
    final String s = "attr=member,beforeCount=5,afterCount=10";

    final ChangeLogEntryAttributeExceededMaxValuesCount c =
         new ChangeLogEntryAttributeExceededMaxValuesCount(s);

    assertNotNull(c);

    assertEquals(c.getAttributeName(), "member");

    assertEquals(c.getBeforeCount(), 5);

    assertEquals(c.getAfterCount(), 10);

    c.hashCode();

    assertNotNull(c.toString());
    assertEquals(c.toString(), s);
  }



  /**
   * Provides test coverage for a valid value string with spaces between
   * elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidValueStringWithSpaces()
         throws Exception
  {
    final String s = "attr = member , beforecount = 10 , aftercount = 5";

    final ChangeLogEntryAttributeExceededMaxValuesCount c =
         new ChangeLogEntryAttributeExceededMaxValuesCount(s);

    assertNotNull(c);

    assertEquals(c.getAttributeName(), "member");

    assertEquals(c.getBeforeCount(), 10);

    assertEquals(c.getAfterCount(), 5);

    c.hashCode();

    assertNotNull(c.toString());
    assertEquals(c.toString(), s);
  }



  /**
   * Provides test coverage for a value string that contains a token without an
   * equal sign to separate the name from the value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testValueStringTokenWithoutEquals()
         throws Exception
  {
    final String s = "attr=member,beforeCount1,afterCount=2";

    new ChangeLogEntryAttributeExceededMaxValuesCount(s);
  }



  /**
   * Provides test coverage for a value string that does not contain an
   * attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testValueStringMissingAttributeName()
         throws Exception
  {
    final String s = "beforeCount=1,afterCount=2";

    new ChangeLogEntryAttributeExceededMaxValuesCount(s);
  }



  /**
   * Provides test coverage for a value string that contains multiple attribute
   * names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testValueStringMultipleAttributeNames()
         throws Exception
  {
    final String s = "attr=member,attr=uniqueMember,beforeCount=1,afterCount=2";

    new ChangeLogEntryAttributeExceededMaxValuesCount(s);
  }



  /**
   * Provides test coverage for a value string that contains a before count that
   * cannot be parsed as an integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testValueStringMalformedBeforeCount()
         throws Exception
  {
    final String s = "attr=member,beforeCount=malformed,afterCount=2";

    new ChangeLogEntryAttributeExceededMaxValuesCount(s);
  }



  /**
   * Provides test coverage for a value string that does not contain a before
   * count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testValueStringMissingBeforeCount()
         throws Exception
  {
    final String s = "attr=member,afterCount=2";

    new ChangeLogEntryAttributeExceededMaxValuesCount(s);
  }



  /**
   * Provides test coverage for a value string that contains multiple before
   * counts.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testValueStringMultipleBeforeCounts()
         throws Exception
  {
    final String s = "attr=member,beforeCount=1,beforeCount=3,afterCount=2";

    new ChangeLogEntryAttributeExceededMaxValuesCount(s);
  }



  /**
   * Provides test coverage for a value string that contains an after count that
   * cannot be parsed as an integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testValueStringMalformedAfterCount()
         throws Exception
  {
    final String s = "attr=member,beforeCount=1,afterCount=malformed";

    new ChangeLogEntryAttributeExceededMaxValuesCount(s);
  }



  /**
   * Provides test coverage for a value string that does not contain a after
   * count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testValueStringMissingAfterCount()
         throws Exception
  {
    final String s = "attr=member,beforeCount=1";

    new ChangeLogEntryAttributeExceededMaxValuesCount(s);
  }



  /**
   * Provides test coverage for a value string that contains multiple after
   * counts.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testValueStringMultipleAfterCounts()
         throws Exception
  {
    final String s = "attr=member,beforeCount=1,afterCount=2,afterCount=3";

    new ChangeLogEntryAttributeExceededMaxValuesCount(s);
  }



  /**
   * Tests the behavior of the {@code equals} method with a {@code null}
   * argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNull()
         throws Exception
  {
    final String s = "attr=member,beforeCount=5,afterCount=10";

    final ChangeLogEntryAttributeExceededMaxValuesCount c =
         new ChangeLogEntryAttributeExceededMaxValuesCount(s);

    assertFalse(c.equals(null));
  }



  /**
   * Tests the behavior of the {@code equals} method when compared with the same
   * object instance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIdentity()
         throws Exception
  {
    final String s = "attr=member,beforeCount=5,afterCount=10";

    final ChangeLogEntryAttributeExceededMaxValuesCount c =
         new ChangeLogEntryAttributeExceededMaxValuesCount(s);

    assertTrue(c.equals(c));

    assertEquals(c.hashCode(), c.hashCode());
  }



  /**
   * Tests the behavior of the {@code equals} method when compared with an
   * object of the wrong type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsDifferentObjectType()
         throws Exception
  {
    final String s = "attr=member,beforeCount=5,afterCount=10";

    final ChangeLogEntryAttributeExceededMaxValuesCount c =
         new ChangeLogEntryAttributeExceededMaxValuesCount(s);

    assertFalse(c.equals(s));
  }



  /**
   * Tests the behavior of the {@code equals} method when compared with an
   * equivalent object with the same value string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsEquivalentSameValueString()
         throws Exception
  {
    final String s = "attr=member,beforeCount=5,afterCount=10";

    final ChangeLogEntryAttributeExceededMaxValuesCount c1 =
         new ChangeLogEntryAttributeExceededMaxValuesCount(s);

    final ChangeLogEntryAttributeExceededMaxValuesCount c2 =
         new ChangeLogEntryAttributeExceededMaxValuesCount(s);

    assertTrue(c1.equals(c2));
    assertTrue(c2.equals(c1));

    assertEquals(c1.hashCode(), c2.hashCode());
  }



  /**
   * Tests the behavior of the {@code equals} method when compared with an
   * equivalent object with different but logically equivalent value strings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsEquivalentValueStrings()
         throws Exception
  {
    final String s1 = "attr=member,beforeCount=5,afterCount=10";
    final String s2 = "attr = member , beforecount = 5 , aftercount = 10";

    final ChangeLogEntryAttributeExceededMaxValuesCount c1 =
         new ChangeLogEntryAttributeExceededMaxValuesCount(s1);

    final ChangeLogEntryAttributeExceededMaxValuesCount c2 =
         new ChangeLogEntryAttributeExceededMaxValuesCount(s2);

    assertTrue(c1.equals(c2));
    assertTrue(c2.equals(c1));

    assertEquals(c1.hashCode(), c2.hashCode());
  }



  /**
   * Tests the behavior of the {@code equals} method when compared with a
   * non-equivalent object with the same value string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNotEquivalent()
       throws Exception
  {
    final String s1 = "attr=member,beforeCount=5,afterCount=10";
    final String s2 = "attr=member,beforeCount=10,afterCount=5";

    final ChangeLogEntryAttributeExceededMaxValuesCount c1 =
         new ChangeLogEntryAttributeExceededMaxValuesCount(s1);

    final ChangeLogEntryAttributeExceededMaxValuesCount c2 =
         new ChangeLogEntryAttributeExceededMaxValuesCount(s2);

    assertFalse(c1.equals(c2));
    assertFalse(c2.equals(c1));

    assertFalse(c1.hashCode() == c2.hashCode());
  }
}
