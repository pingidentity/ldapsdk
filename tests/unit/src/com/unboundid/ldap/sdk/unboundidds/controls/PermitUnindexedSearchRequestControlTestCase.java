/*
 * Copyright 2018-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2023 Ping Identity Corporation
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
 * Copyright (C) 2018-2023 Ping Identity Corporation
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
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the permit unindexed search
 * request control.
 */
public final class PermitUnindexedSearchRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the control behavior when using the default constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultConstructor()
         throws Exception
  {
    PermitUnindexedSearchRequestControl c =
         new PermitUnindexedSearchRequestControl();

    c = new PermitUnindexedSearchRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.55");

    assertFalse(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the control behavior with an explicit criticality of {@code true}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplicitCriticalityTrue()
         throws Exception
  {
    PermitUnindexedSearchRequestControl c =
         new PermitUnindexedSearchRequestControl(true);

    c = new PermitUnindexedSearchRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.55");

    assertTrue(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the control behavior with an explicit criticality of {@code false}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplicitCriticalityFalse()
         throws Exception
  {
    PermitUnindexedSearchRequestControl c =
         new PermitUnindexedSearchRequestControl(false);

    c = new PermitUnindexedSearchRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.55");

    assertFalse(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to decode a control that has a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithValue()
         throws Exception
  {
    final Control genericControl = new Control("1.3.6.1.4.1.30221.2.5.55",
         false, new ASN1OctetString("unexpected value"));

    new PermitUnindexedSearchRequestControl(genericControl);
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControl()
          throws Exception
  {
    final PermitUnindexedSearchRequestControl c =
         new PermitUnindexedSearchRequestControl(false);

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 3);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.FALSE);

    assertFalse(controlObject.hasField("value-base64"));

    assertFalse(controlObject.hasField("value-json"));


    PermitUnindexedSearchRequestControl decodedControl =
         PermitUnindexedSearchRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNull(decodedControl.getValue());


    decodedControl =
         (PermitUnindexedSearchRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNull(decodedControl.getValue());
  }
}
