/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;



/**
 * This class provides a set of test cases for the IntermediateResponse class.
 */
public class IntermediateResponseTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with both OID and value elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1OIDAndValue()
         throws Exception
  {
    IntermediateResponse ir =
         new IntermediateResponse("1.2.3.4", new ASN1OctetString());
    ir = new IntermediateResponse(ir);

    assertNotNull(ir);

    assertNotNull(ir.getOID());
    assertEquals(ir.getOID(), "1.2.3.4");

    assertNotNull(ir.getValue());
    assertEquals(ir.getValue(), new ASN1OctetString());

    assertNotNull(ir.getControls());
    assertEquals(ir.getControls().length, 0);
    assertNull(ir.getControl("1.2.3.5"));
    assertNull(ir.getControl("1.2.3.6"));

    assertNotNull(ir.getIntermediateResponseName());
    assertEquals(ir.getIntermediateResponseName(), "1.2.3.4");

    assertNull(ir.valueToString());

    assertNotNull(ir.toString());

    assertEquals(ir.getMessageID(), -1);
  }



  /**
   * Tests the first constructor with an OID but no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1OID()
         throws Exception
  {
    IntermediateResponse ir =
         new IntermediateResponse("1.2.3.4", null);
    ir = new IntermediateResponse(ir);

    assertNotNull(ir);

    assertNotNull(ir.getOID());
    assertEquals(ir.getOID(), "1.2.3.4");

    assertNull(ir.getValue());

    assertNotNull(ir.getControls());
    assertEquals(ir.getControls().length, 0);
    assertNull(ir.getControl("1.2.3.5"));
    assertNull(ir.getControl("1.2.3.6"));

    assertNotNull(ir.getIntermediateResponseName());
    assertEquals(ir.getIntermediateResponseName(), "1.2.3.4");

    assertNull(ir.valueToString());

    assertNotNull(ir.toString());

    assertEquals(ir.getMessageID(), -1);
  }



  /**
   * Tests the first constructor with a value but no OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Value()
         throws Exception
  {
    IntermediateResponse ir =
         new IntermediateResponse(null, new ASN1OctetString());
    ir = new IntermediateResponse(ir);

    assertNotNull(ir);

    assertNull(ir.getOID());

    assertNotNull(ir.getValue());
    assertEquals(ir.getValue(), new ASN1OctetString());

    assertNotNull(ir.getControls());
    assertEquals(ir.getControls().length, 0);
    assertNull(ir.getControl("1.2.3.5"));
    assertNull(ir.getControl("1.2.3.6"));

    assertNull(ir.getIntermediateResponseName());

    assertNull(ir.valueToString());

    assertNotNull(ir.toString());

    assertEquals(ir.getMessageID(), -1);
  }



  /**
   * Tests the second constructor with both OID and value elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2OIDAndValue()
         throws Exception
  {
    IntermediateResponse ir =
         new IntermediateResponse(1, "1.2.3.4", new ASN1OctetString());
    ir = new IntermediateResponse(ir);

    assertNotNull(ir);

    assertNotNull(ir.getOID());
    assertEquals(ir.getOID(), "1.2.3.4");

    assertNotNull(ir.getValue());
    assertEquals(ir.getValue(), new ASN1OctetString());

    assertNotNull(ir.getControls());
    assertEquals(ir.getControls().length, 0);
    assertNull(ir.getControl("1.2.3.5"));
    assertNull(ir.getControl("1.2.3.6"));

    assertNotNull(ir.getIntermediateResponseName());
    assertEquals(ir.getIntermediateResponseName(), "1.2.3.4");

    assertNull(ir.valueToString());

    assertNotNull(ir.toString());

    assertEquals(ir.getMessageID(), 1);
  }



  /**
   * Tests the first constructor with an OID but no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2OID()
         throws Exception
  {
    IntermediateResponse ir =
         new IntermediateResponse(1, "1.2.3.4", null);
    ir = new IntermediateResponse(ir);

    assertNotNull(ir);

    assertNotNull(ir.getOID());
    assertEquals(ir.getOID(), "1.2.3.4");

    assertNull(ir.getValue());

    assertNotNull(ir.getControls());
    assertEquals(ir.getControls().length, 0);
    assertNull(ir.getControl("1.2.3.5"));
    assertNull(ir.getControl("1.2.3.6"));

    assertNotNull(ir.getIntermediateResponseName());
    assertEquals(ir.getIntermediateResponseName(), "1.2.3.4");

    assertNull(ir.valueToString());

    assertNotNull(ir.toString());

    assertEquals(ir.getMessageID(), 1);
  }



  /**
   * Tests the first constructor with a value but no OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Value()
         throws Exception
  {
    IntermediateResponse ir =
         new IntermediateResponse(1, null, new ASN1OctetString());
    ir = new IntermediateResponse(ir);

    assertNotNull(ir);

    assertNull(ir.getOID());

    assertNotNull(ir.getValue());
    assertEquals(ir.getValue(), new ASN1OctetString());

    assertNotNull(ir.getControls());
    assertEquals(ir.getControls().length, 0);
    assertNull(ir.getControl("1.2.3.5"));
    assertNull(ir.getControl("1.2.3.6"));

    assertNull(ir.getIntermediateResponseName());

    assertNull(ir.valueToString());

    assertNotNull(ir.toString());

    assertEquals(ir.getMessageID(), 1);
  }



  /**
   * Tests the second constructor with a {@code null} set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NullControls()
         throws Exception
  {
    IntermediateResponse ir =
         new IntermediateResponse("1.2.3.4", new ASN1OctetString(), null);
    ir = new IntermediateResponse(ir);

    assertNotNull(ir);

    assertNotNull(ir.getOID());
    assertEquals(ir.getOID(), "1.2.3.4");

    assertNotNull(ir.getValue());
    assertEquals(ir.getValue(), new ASN1OctetString());

    assertNotNull(ir.getControls());
    assertEquals(ir.getControls().length, 0);
    assertNull(ir.getControl("1.2.3.5"));
    assertNull(ir.getControl("1.2.3.6"));

    assertNotNull(ir.getIntermediateResponseName());
    assertEquals(ir.getIntermediateResponseName(), "1.2.3.4");

    assertNull(ir.valueToString());

    assertNotNull(ir.toString());

    assertEquals(ir.getMessageID(), -1);
  }



  /**
   * Tests the second constructor with an empty set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3EmptyControls()
         throws Exception
  {
    Control[] controls = new Control[0];

    IntermediateResponse ir =
         new IntermediateResponse("1.2.3.4", new ASN1OctetString(), controls);
    ir = new IntermediateResponse(ir);

    assertNotNull(ir);

    assertNotNull(ir.getOID());
    assertEquals(ir.getOID(), "1.2.3.4");

    assertNotNull(ir.getValue());
    assertEquals(ir.getValue(), new ASN1OctetString());

    assertNotNull(ir.getControls());
    assertEquals(ir.getControls().length, 0);
    assertNull(ir.getControl("1.2.3.5"));
    assertNull(ir.getControl("1.2.3.6"));

    assertNotNull(ir.getIntermediateResponseName());
    assertEquals(ir.getIntermediateResponseName(), "1.2.3.4");

    assertNull(ir.valueToString());

    assertNotNull(ir.toString());

    assertEquals(ir.getMessageID(), -1);
  }



  /**
   * Tests the second constructor with a single control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3SingleControl()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.5")
    };

    IntermediateResponse ir =
         new IntermediateResponse("1.2.3.4", new ASN1OctetString(), controls);
    ir = new IntermediateResponse(ir);

    assertNotNull(ir);

    assertNotNull(ir.getOID());
    assertEquals(ir.getOID(), "1.2.3.4");

    assertNotNull(ir.getValue());
    assertEquals(ir.getValue(), new ASN1OctetString());

    assertNotNull(ir.getControls());
    assertEquals(ir.getControls().length, 1);
    assertNotNull(ir.getControl("1.2.3.5"));
    assertNull(ir.getControl("1.2.3.6"));

    assertNotNull(ir.getIntermediateResponseName());
    assertEquals(ir.getIntermediateResponseName(), "1.2.3.4");

    assertNull(ir.valueToString());

    assertNotNull(ir.toString());

    assertEquals(ir.getMessageID(), -1);
  }



  /**
   * Tests the second constructor with multiple controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3MultipleControls()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.5"),
      new Control("1.2.3.6"),
    };

    IntermediateResponse ir =
         new IntermediateResponse("1.2.3.4", new ASN1OctetString(), controls);
    ir = new IntermediateResponse(ir);

    assertNotNull(ir);

    assertNotNull(ir.getOID());
    assertEquals(ir.getOID(), "1.2.3.4");

    assertNotNull(ir.getValue());
    assertEquals(ir.getValue(), new ASN1OctetString());

    assertNotNull(ir.getControls());
    assertEquals(ir.getControls().length, 2);
    assertNotNull(ir.getControl("1.2.3.5"));
    assertNotNull(ir.getControl("1.2.3.6"));

    assertNotNull(ir.getIntermediateResponseName());
    assertEquals(ir.getIntermediateResponseName(), "1.2.3.4");

    assertNull(ir.valueToString());

    assertNotNull(ir.toString());

    assertEquals(ir.getMessageID(), -1);
  }
}
