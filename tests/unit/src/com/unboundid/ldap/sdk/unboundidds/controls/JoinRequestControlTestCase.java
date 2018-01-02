/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code JoinRequestControl}
 * class.
 */
public class JoinRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Performs a set of tests covering the join request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testJoinRequestControl()
         throws Exception
  {
    JoinRequestValue v = new JoinRequestValue(
         JoinRule.createDNJoin("member"),
         JoinBaseDN.createUseCustomBaseDN("dc=example,dc=com"), null, null,
         null, null, null, false, null);

    JoinRequestControl c = new JoinRequestControl(v);
    c = new JoinRequestControl(c);

    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.9");

    assertTrue(c.isCritical());

    assertNotNull(c.getJoinRequestValue());
    assertEquals(c.getJoinRequestValue().getJoinRule().getType(),
                 JoinRule.JOIN_TYPE_DN);
    assertEquals(c.getJoinRequestValue().getJoinRule().getSourceAttribute(),
                 "member");

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of attempting to decode a control with no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    new JoinRequestControl(new Control("1.3.6.1.4.1.30221.2.5.9", true));
  }



  /**
   * Tests the behavior of attempting to decode a control whose value is not a
   * sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new JoinRequestControl(new Control("1.3.6.1.4.1.30221.2.5.9", true,
              new ASN1OctetString(new byte[1])));
  }
}
