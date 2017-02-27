/*
 * Copyright 2009-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2017 UnboundID Corp.
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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;



/**
 * This class provides test coverage for the {@code LDAPModification} class.
 */
public class LDAPModificationTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides coverage for a modification created from a modification type and
   * attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithOpTypeAndAttr()
         throws Exception
  {
    LDAPModification m = new LDAPModification(2,
         new LDAPAttribute("foo", "bar"));

    assertNotNull(m);

    assertEquals(m.getOp(), 2);

    assertNotNull(m.getAttribute());
    assertEquals(m.getAttribute().getName(), "foo");
    assertEquals(m.getAttribute().getStringValueArray()[0], "bar");

    assertNotNull(m.toModification());
    assertEquals(m.toModification().getModificationType(),
         ModificationType.REPLACE);
    assertEquals(m.toModification().getAttributeName(), "foo");

    assertNotNull(m.toString());
  }



  /**
   * Provides coverage for a modification created from an SDK modification.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithSDKModification()
         throws Exception
  {
    LDAPModification m = new LDAPModification(new Modification(
         ModificationType.ADD, "foo", "bar"));

    assertNotNull(m);

    assertEquals(m.getOp(), 0);

    assertNotNull(m.getAttribute());
    assertEquals(m.getAttribute().getName(), "foo");
    assertEquals(m.getAttribute().getStringValueArray()[0], "bar");

    assertNotNull(m.toModification());
    assertEquals(m.toModification().getModificationType(),
         ModificationType.ADD);
    assertEquals(m.toModification().getAttributeName(), "foo");

    assertNotNull(m.toString());
  }
}
