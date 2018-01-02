/*
 * Copyright 2010-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2010-2018 Ping Identity Corporation
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



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the
 * {@code ResumeWithTokenStartingPoint} class.
 */
public final class ResumeWithTokenStartingPointTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for this starting point.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateStartingPoint()
         throws Exception
  {
    final ASN1OctetString token = new ASN1OctetString("foo");
    final ResumeWithTokenStartingPoint sp =
         new ResumeWithTokenStartingPoint(token);

    assertNotNull(sp.encode());

    assertNotNull(sp.getResumeToken());
    assertTrue(Arrays.equals(sp.getResumeToken().getValue(), token.getValue()));

    assertNotNull(sp.toString());
  }
}
