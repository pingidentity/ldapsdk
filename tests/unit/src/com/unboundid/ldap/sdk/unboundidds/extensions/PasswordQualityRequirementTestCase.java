/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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



import java.util.Collections;
import java.util.LinkedHashMap;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the password quality requirement
 * class.
 */
public final class PasswordQualityRequirementTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the class with only a description and no client-side
   * validation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoClientSideValidation()
         throws Exception
  {
    PasswordQualityRequirement r =
         new PasswordQualityRequirement("description without validation");

    r = PasswordQualityRequirement.decode(r.encode());
    assertNotNull(r);

    assertNotNull(r.getDescription());
    assertEquals(r.getDescription(), "description without validation");

    assertNull(r.getClientSideValidationType());

    assertNotNull(r.getClientSideValidationProperties());
    assertTrue(r.getClientSideValidationProperties().isEmpty());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the class with a description and client-side
   * validation type but no validation properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testClientSideValidationTypeWithoutProperties()
         throws Exception
  {
    PasswordQualityRequirement r = new PasswordQualityRequirement(
         "description and type without properties", "validation-type",
         Collections.<String,String>emptyMap());

    r = PasswordQualityRequirement.decode(r.encode());
    assertNotNull(r);

    assertNotNull(r.getDescription());
    assertEquals(r.getDescription(), "description and type without properties");

    assertNotNull(r.getClientSideValidationType());
    assertEquals(r.getClientSideValidationType(), "validation-type");

    assertNotNull(r.getClientSideValidationProperties());
    assertTrue(r.getClientSideValidationProperties().isEmpty());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the class with a description and client-side
   * validation type but no validation properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testClientSideValidationPropertiesWithoutType()
         throws Exception
  {
    final LinkedHashMap<String,String> properties =
         new LinkedHashMap<String,String>(2);
    properties.put("minimum-length", "8");
    properties.put("maximum-length", "20");

    new PasswordQualityRequirement("description and properties without type",
         null, properties);
  }



  /**
   * Tests the behavior of the class with a description and client-side type
   * and properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testClientSideValidationTypeAndProperties()
         throws Exception
  {
    final LinkedHashMap<String,String> properties =
         new LinkedHashMap<String,String>(2);
    properties.put("minimum-length", "8");
    properties.put("maximum-length", "20");

    PasswordQualityRequirement r = new PasswordQualityRequirement(
         "description and type and properties", "length", properties);

    r = PasswordQualityRequirement.decode(r.encode());
    assertNotNull(r);

    assertNotNull(r.getDescription());
    assertEquals(r.getDescription(), "description and type and properties");

    assertNotNull(r.getClientSideValidationType());
    assertEquals(r.getClientSideValidationType(), "length");

    assertNotNull(r.getClientSideValidationProperties());
    assertFalse(r.getClientSideValidationProperties().isEmpty());
    assertEquals(r.getClientSideValidationProperties().size(), 2);
    assertEquals(r.getClientSideValidationProperties().get("minimum-length"),
         "8");
    assertEquals(r.getClientSideValidationProperties().get("maximum-length"),
         "20");

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode an encoded requirement that is
   * not encoded as an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeElementNotSequence()
         throws Exception
  {
    PasswordQualityRequirement.decode(new ASN1OctetString("not a sequence"));
  }



  /**
   * Tests the behavior when trying to decode an encoded requirement that is an
   * empty ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeEmptySequence()
         throws Exception
  {
    PasswordQualityRequirement.decode(new ASN1Sequence());
  }



  /**
   * Tests the behavior when trying to decode an encoded requirement whose
   * sequence includes an element with an invalid type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSequenceInvalidElement()
         throws Exception
  {
    PasswordQualityRequirement.decode(new ASN1Sequence(
         new ASN1OctetString("description"),
         new ASN1OctetString((byte) 0x12, "Not even close to a valid type")));
  }



  /**
   * Tests the behavior when trying to decode an encoded requirement whose
   * sequence includes a client-side validation info component with an element
   * with an invalid type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSequenceInvalidClientSideValidationElement()
         throws Exception
  {
    PasswordQualityRequirement.decode(new ASN1Sequence(
         new ASN1OctetString("description"),
         new ASN1Sequence((byte) 0xA0,
              new ASN1OctetString("validation-type"),
              new ASN1OctetString((byte) 0x12, "Wrong type"))));
  }
}
