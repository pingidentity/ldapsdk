/*
 * Copyright 2012-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2012-2019 Ping Identity Corporation
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



import java.util.Date;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the subtree accessibility
 * restriction class.
 */
public final class SubtreeAccessibilityRestrictionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with a bypass user defined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithBypassUser()
         throws Exception
  {
    final Date effectiveTime = new Date();

    final SubtreeAccessibilityRestriction r =
         new SubtreeAccessibilityRestriction("ou=subtree,dc=example,dc=com",
              SubtreeAccessibilityState.READ_ONLY_BIND_ALLOWED,
              "uid=bypass,dc=example,dc=com", effectiveTime);

    assertNotNull(r.getSubtreeBaseDN());
    assertDNsEqual(r.getSubtreeBaseDN(), "ou=subtree,dc=example,dc=com");

    assertNotNull(r.getAccessibilityState());
    assertEquals(r.getAccessibilityState(),
         SubtreeAccessibilityState.READ_ONLY_BIND_ALLOWED);

    assertNotNull(r.getBypassUserDN());
    assertDNsEqual(r.getBypassUserDN(), "uid=bypass,dc=example,dc=com");

    assertNotNull(r.getEffectiveTime());
    assertEquals(r.getEffectiveTime(), effectiveTime);

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior without a bypass user defined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutBypassUser()
         throws Exception
  {
    final Date effectiveTime = new Date();

    final SubtreeAccessibilityRestriction r =
         new SubtreeAccessibilityRestriction("ou=subtree,dc=example,dc=com",
              SubtreeAccessibilityState.READ_ONLY_BIND_ALLOWED, null,
              effectiveTime);

    assertNotNull(r.getSubtreeBaseDN());
    assertDNsEqual(r.getSubtreeBaseDN(), "ou=subtree,dc=example,dc=com");

    assertNotNull(r.getAccessibilityState());
    assertEquals(r.getAccessibilityState(),
         SubtreeAccessibilityState.READ_ONLY_BIND_ALLOWED);

    assertNull(r.getBypassUserDN());

    assertNotNull(r.getEffectiveTime());
    assertEquals(r.getEffectiveTime(), effectiveTime);

    assertNotNull(r.toString());
  }
}
