/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.transformations;



import java.util.Arrays;
import java.util.Random;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for scramble attribute
 * transformations.
 */
public final class ScrambleAttributeTransformationTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the behavior when provided with a null entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullEntry()
         throws Exception
  {
    final ScrambleAttributeTransformation t =
         new ScrambleAttributeTransformation("description");

    assertNull(t.transformEntry(null));
  }



  /**
   * Provides test coverage for the behavior when provided with a null change
   * record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullChangeRecord()
         throws Exception
  {
    final ScrambleAttributeTransformation t =
         new ScrambleAttributeTransformation(Arrays.asList("description"));

    assertNull(t.transformChangeRecord(null));
  }



  /**
   * Provides basic test coverage for the transformEntry method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformEntry()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final ScrambleAttributeTransformation t =
         new ScrambleAttributeTransformation(schema, 0L, true,
              Arrays.asList("description"), Arrays.asList("field1", "field2"));

    final Entry e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo1BAR+bAz"));

    assertNotNull(e);

    assertNotNull(e.getAttributeValue("description"));
    assertFalse(e.getAttributeValue("description").equals("foo1BAR+bAz"));
    assertEquals(e.getAttributeValue("description").length(), 11);
    assertTrue(e.getAttributeValue("description").matches(
         "^[a-z][a-z][a-z][0-9][A-Z][A-Z][A-Z]\\+[a-z][A-Z][a-z]$"));
  }



  /**
   * Provides basic test coverage for the transformChangeRecord method for an
   * add record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformAddChangeRecord()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final ScrambleAttributeTransformation t =
         new ScrambleAttributeTransformation(schema, 0L, true,
              Arrays.asList("description"), Arrays.asList("field1", "field2"));

    final LDIFAddChangeRecord r =
         (LDIFAddChangeRecord)
         t.transformChangeRecord(new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: foo1BAR+bAz")));

    assertNotNull(r);

    assertNotNull(r.getEntryToAdd().getAttributeValue("description"));
    assertFalse(r.getEntryToAdd().getAttributeValue("description").equals(
         "foo1BAR+bAz"));
    assertEquals(r.getEntryToAdd().getAttributeValue("description").length(),
         11);
    assertTrue(r.getEntryToAdd().getAttributeValue("description").matches(
         "^[a-z][a-z][a-z][0-9][A-Z][A-Z][A-Z]\\+[a-z][A-Z][a-z]$"));
  }



  /**
   * Provides basic test coverage for the transformChangeRecord method for a
   * delete record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformDeleteChangeRecord()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final ScrambleAttributeTransformation t =
         new ScrambleAttributeTransformation(schema, 0L, true,
              Arrays.asList("uid"), null);

    final LDIFChangeRecord r = t.transformChangeRecord(
         new LDIFDeleteChangeRecord("uid=user.1,ou=People,dc=example,dc=com"));
    assertNotNull(r);
    assertFalse(r.getDN().equals("uid=user.1,ou=People,dc=example,dc=com"));
    assertTrue(r.getDN().startsWith("uid="));
    assertTrue(r.getDN().endsWith(",ou=People,dc=example,dc=com"));
  }



  /**
   * Provides basic test coverage for the transformChangeRecord method for a
   * modify record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformModifyChangeRecord()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final ScrambleAttributeTransformation t =
         new ScrambleAttributeTransformation(schema, 0L, true,
              Arrays.asList("uid", "ou"), null);

    final LDIFChangeRecord r = t.transformChangeRecord(
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: uid=user.1,ou=People,dc=example,dc=com",
              "changetype: modify",
              "add: uid",
              "uid: user.2",
              "-",
              "add: ou",
              "ou: foo",
              "-",
              "add: seeAlso",
              "seeAlso: uid=something,ou=something else,dc=example,dc=com")));
    assertNotNull(r);
  }



  /**
   * Provides basic test coverage for the transformChangeRecord method for a
   * modify DN record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformModifyDNChangeRecord()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final ScrambleAttributeTransformation t =
         new ScrambleAttributeTransformation(schema, 0L, true,
              Arrays.asList("uid", "ou"), null);

    final LDIFChangeRecord r = t.transformChangeRecord(
         new LDIFModifyDNChangeRecord(
              "uid=user.1,ou=People,dc=example,dc=com", "uid=user.2", true,
              "ou=Users,dc=example,dc=com"));
    assertNotNull(r);
  }



  /**
   * Provides test coverage for the scrambleAttribute method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testScrambleAttribute()
         throws Exception
  {
    final Schema standardSchema = Schema.getDefaultStandardSchema();

    final AttributeTypeDefinition booleanAttr =
         new AttributeTypeDefinition("test-boolean-attr-oid",
              "test-boolean-attr", null, null, null, null,
              "1.3.6.1.4.1.1466.115.121.1.7", false, null);
    final AttributeTypeDefinition integerAttr =
         new AttributeTypeDefinition("test-integer-attr-oid",
              "test-integer-attr", null, null, null, null,
              "1.3.6.1.4.1.1466.115.121.1.27", false, null);
    final AttributeTypeDefinition binaryAttr =
         new AttributeTypeDefinition("test-binary-attr-oid",
              "test-binary-attr", null, null, null, null,
              "1.3.6.1.4.1.1466.115.121.1.40", false, null);
    final AttributeTypeDefinition timestampAttr =
         new AttributeTypeDefinition("test-timestamp-attr-oid",
              "test-timestamp-attr", null, null, null, null,
              "1.3.6.1.4.1.1466.115.121.1.24", false, null);
    final Schema customSchema = new Schema(new Entry(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: " + booleanAttr.toString(),
         "attributeTypes: " + integerAttr.toString(),
         "attributeTypes: " + binaryAttr.toString(),
         "attributeTypes: " + timestampAttr.toString()));

    final Schema schema = Schema.mergeSchemas(standardSchema, customSchema);
    final ScrambleAttributeTransformation t =
         new ScrambleAttributeTransformation(schema, 0L, true,
              Arrays.asList("uid", "userPassword", "authPassword",
                   "description", "seeAlso", "telephoneNumber",
                   "test-boolean-attr", "test-integer-attr",
                   "test-binary-attr", "test-timestamp-attr"),
              Arrays.asList("field1", "field2"));


    // Test the behavior when trying to scramble a null attribute.
    assertNull(t.scrambleAttribute(null));


    // Test the behavior when trying to scramble an attribute that doesn't have
    // any values.
    assertEquals(t.scrambleAttribute(new Attribute("description")),
         new Attribute("description"));


    // Test the behavior when trying to scramble an attribute that isn't
    // configured to be scrambled.
    assertEquals(t.scrambleAttribute(
         new Attribute("objectClass", "top", "domain")),
         new Attribute("objectClass", "top", "domain"));


    // Test the behavior when trying to scramble an attribute with a Boolean
    // syntax.
    boolean gotTrue = false;
    boolean gotFalse = false;
    for (int i=0; i < 100; i++)
    {
      final Attribute a =
           t.scrambleAttribute(new Attribute("test-boolean-attr", "TRUE"));
      if (a.hasValue("TRUE"))
      {
        gotTrue = true;
      }
      else if (a.hasValue("FALSE"))
      {
        gotFalse = true;
      }
      else
      {
        fail("Unexpected value " + a.getValue() +
             " encountered when TRUE or FALSE was expected");
      }
    }


    // Test the behavior when trying to scramble a multivalued attribute with a
    // Boolean syntax.
    assertEquals(
         t.scrambleAttribute(
              new Attribute("test-boolean-attr", "FALSE", "TRUE")),
         new Attribute("test-boolean-attr", "TRUE", "FALSE"));


    // Test the behavior when trying to scramble an attribute with a DN syntax.
    assertEquals(
         t.scrambleAttribute(new Attribute("seeAlso", "")).getValueAsDN(),
         DN.NULL_DN);
    assertFalse(
         t.scrambleAttribute(
              new Attribute("seeAlso",
                   "description=foo,dc=example,dc=com")).equals(
              new Attribute("seeAlso", "description=foo,dc=example,dc=com")));
    assertEquals(
         t.scrambleAttribute(
              new Attribute("seeAlso", "description=foo,dc=example,dc=com")),
         new Attribute("seeAlso",
              "description=" + t.scrambleString("foo") + ",dc=example,dc=com"));


    // Get coverage for an attempt to scramble an attribute with a DN syntax
    // but a value that isn't a valid DN.
    t.scrambleAttribute(new Attribute("seeAlso", "not-a-valid-dn"));


    // Test the behavior when trying to scramble an attribute with an integer
    // syntax.
    assertFalse(
         t.scrambleAttribute(
              new Attribute("test-integer-attr", "12345")).equals(
                   new Attribute("test-integer-attr", "12345")));
    assertTrue(
         t.scrambleAttribute(
              new Attribute("test-integer-attr", "12345")).getValue().matches(
              "^[1-9][0-9][0-9][0-9][0-9]$"));


    // Test the behavior when trying to scramble an attribute with a generalized
    // time syntax.
    assertFalse(
         t.scrambleAttribute(new Attribute("test-timestamp-attr",
              "20160102030405.678Z")).getValue().equals("20160102030405.678Z"));
    StaticUtils.decodeGeneralizedTime(
         t.scrambleAttribute(new Attribute("test-timestamp-attr",
              "20160102030405.678Z")).getValue());


    // Test the behavior when trying to scramble a binary value.
    final Random random = new Random();
    final byte[] randomBytes = new byte[50];
    random.nextBytes(randomBytes);
    assertFalse(Arrays.equals(
         t.scrambleAttribute(new Attribute("test-binary-attr",
              randomBytes)).getValueByteArray(),
         randomBytes));


    // Test the behavior when trying to scramble a userPassword value without
    // any scheme.
    assertFalse(t.scrambleAttribute(new Attribute("userPassword",
         "password")).getValue().equals("password"));
    assertFalse(t.scrambleAttribute(new Attribute("userPassword",
         "password")).getValue().startsWith("{"));


    // Test the behavior when trying to scramble a userPassword value that has a
    // scheme.
    assertFalse(t.scrambleAttribute(new Attribute("userPassword",
         "{CLEAR}password")).getValue().equals("{CLEAR}password"));
    assertTrue(t.scrambleAttribute(new Attribute("userPassword",
         "{CLEAR}password")).getValue().startsWith("{CLEAR}"));


    // Test the behavior when trying to scramble a userPassword value that has a
    // scheme.
    assertTrue(t.scrambleAttribute(new Attribute("authPassword",
         "SHA1$xxxx$yyyy")).getValue().startsWith("SHA1$"));
    assertFalse(t.scrambleAttribute(new Attribute("authPassword",
         "SHA1$xxxx$yyyy")).getValue().equals("SHA1$xxxx$yyyy"));


    // Get coverage for the case in which an attribute value is a JSON object.
    t.scrambleAttribute(new Attribute("description",
         "{ \"field1\":\"xxx\", \"field2\":\"yyy\", \"field3\":\"zzz\" }"));
  }



  /**
   * Provides test coverage for the ability to scramble generalized time values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testScrambleGeneralizedTime()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final ScrambleAttributeTransformation t =
         new ScrambleAttributeTransformation(schema, 0L, true,
              Arrays.asList("uid", "userPassword", "description", "seeAlso",
                   "telephoneNumber", "test-boolean-attr", "test-integer-attr",
                   "test-binary-attr", "test-timestamp-attr"),
              Arrays.asList("field1", "field2"));


    assertNull(t.scrambleGeneralizedTime(null));


    final long now = System.currentTimeMillis();
    final long oneHourAgo = now - 3600000L;
    long scrambledTimestamp = StaticUtils.decodeGeneralizedTime(
         t.scrambleGeneralizedTime(
              StaticUtils.encodeGeneralizedTime(oneHourAgo))).getTime();
    assertTrue(scrambledTimestamp < now);


    final long oneHourFromNow = now + 3600000L;
    scrambledTimestamp = StaticUtils.decodeGeneralizedTime(
         t.scrambleGeneralizedTime(
              StaticUtils.encodeGeneralizedTime(oneHourFromNow))).getTime();
    assertTrue(scrambledTimestamp > now);


    final String scrambledStr =
         t.scrambleGeneralizedTime("20160102030405-0500");
    assertEquals(scrambledStr.length(), 19);
    assertTrue(scrambledStr.endsWith("-0500"),
         "Unexpected scrambled generalized time:  " + scrambledStr);
    for (int i=0; i < 14; i++)
    {
      assertTrue((scrambledStr.charAt(i) >= '0') &&
           (scrambledStr.charAt(i) <= '9'));
    }


    t.scrambleGeneralizedTime("malformed");
  }



  /**
   * Provides test coverage for the ability to scramble numeric values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testScrambleNumericValue()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final ScrambleAttributeTransformation t =
         new ScrambleAttributeTransformation(schema, 0L, true,
              Arrays.asList("uid", "userPassword", "description", "seeAlso",
                   "telephoneNumber", "test-boolean-attr", "test-integer-attr",
                   "test-binary-attr", "test-timestamp-attr"),
              Arrays.asList("field1", "field2"));


    assertNull(t.scrambleNumericValue(null));


    assertEquals(t.scrambleNumericValue("-12345").length(), 6);
    assertTrue(t.scrambleNumericValue("-12345").startsWith("-"));
    assertFalse(t.scrambleNumericValue("-12345").startsWith("-0"));

    t.scrambleNumericValue("123-456-7890");

    t.scrambleNumericValue("+1 (123) 456-7890");

    t.scrambleNumericValue("malformed");
  }



  /**
   * Provides test coverage for the ability to scramble binary values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testScrambleBinaryValue()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final ScrambleAttributeTransformation t =
         new ScrambleAttributeTransformation(schema, 0L, true,
              Arrays.asList("uid", "userPassword", "description", "seeAlso",
                   "telephoneNumber", "test-boolean-attr", "test-integer-attr",
                   "test-binary-attr", "test-timestamp-attr"),
              Arrays.asList("field1", "field2"));


    assertNull(t.scrambleBinaryValue(null));

    final byte[] b = new byte[256];
    for (int i=0; i < 256; i++)
    {
      b[i] = (byte) (i & 0xFF);
    }

    t.scrambleBinaryValue(b);
  }



  /**
   * Provides test coverage for the ability to scramble encoded passwords.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testScrambleEncodedPassword()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final ScrambleAttributeTransformation t =
         new ScrambleAttributeTransformation(schema, 0L, true,
              Arrays.asList("uid", "userPassword", "description", "seeAlso",
                   "telephoneNumber", "test-boolean-attr", "test-integer-attr",
                   "test-binary-attr", "test-timestamp-attr"),
              Arrays.asList("field1", "field2"));


    assertNull(t.scrambleEncodedPassword(null));

    assertTrue(t.scrambleEncodedPassword("{SSHA256}abcdefg").startsWith(
         "{SSHA256}"));
    assertFalse(t.scrambleEncodedPassword("{SSHA256}abcdefg").equals(
         "{SSHA256}abcdefg"));

    assertTrue(t.scrambleEncodedPassword("SHA256$abc$def").startsWith(
         "SHA256$"));
    assertFalse(t.scrambleEncodedPassword("SHA256$abc$def").equals(
         "SHA256$abc$def"));

    t.scrambleEncodedPassword("malformed");
  }



  /**
   * Provides test coverage for the ability to scramble JSON objects when only
   * specific fields should be scrambled.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testScrambleJSONObjectSpecificFields()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final ScrambleAttributeTransformation t =
         new ScrambleAttributeTransformation(schema, 0L, true,
              Arrays.asList("uid", "userPassword", "description", "seeAlso",
                   "telephoneNumber", "test-boolean-attr", "test-integer-attr",
                   "test-binary-attr", "test-timestamp-attr"),
              Arrays.asList("field1", "field2"));


    assertNull(t.scrambleJSONObject(null));

    t.scrambleJSONObject("malformed");

    new JSONObject(t.scrambleJSONObject("{}"));

    new JSONObject(t.scrambleJSONObject("{ \"field1\":true }"));
    new JSONObject(t.scrambleJSONObject("{ \"field1\":null }"));
    new JSONObject(t.scrambleJSONObject("{ \"field1\":1234 }"));
    new JSONObject(t.scrambleJSONObject("{ \"field1\":1234.567 }"));
    new JSONObject(t.scrambleJSONObject("{ \"field1\":\"foo\" }"));
    new JSONObject(t.scrambleJSONObject("{ \"field1\":{  } }"));
    new JSONObject(t.scrambleJSONObject("{ \"field1\":{ \"a\":\"b\" } }"));
    new JSONObject(t.scrambleJSONObject("{ \"field1\":[ 1, 2, 3 ] }"));

    new JSONObject(t.scrambleJSONObject("{ \"field3\":true }"));
    new JSONObject(t.scrambleJSONObject("{ \"field3\":null }"));
    new JSONObject(t.scrambleJSONObject("{ \"field3\":1234 }"));
    new JSONObject(t.scrambleJSONObject("{ \"field3\":1234.567 }"));
    new JSONObject(t.scrambleJSONObject("{ \"field3\":\"foo\" }"));
    new JSONObject(t.scrambleJSONObject("{ \"field3\":{  } }"));
    new JSONObject(t.scrambleJSONObject("{ \"field3\":{ \"field1\":\"b\" } }"));
    new JSONObject(t.scrambleJSONObject("{ \"field3\":[ 1, 2, 3 ] }"));
  }



  /**
   * Provides edge-case coverage for the scramble DN methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testScrambleDNEdgeCase()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final ScrambleAttributeTransformation t =
         new ScrambleAttributeTransformation(schema, 0L, true,
              Arrays.asList("uid", "userPassword", "description", "seeAlso",
                   "telephoneNumber", "test-boolean-attr", "test-integer-attr",
                   "test-binary-attr", "test-timestamp-attr"),
              Arrays.asList("field1", "field2"));

    assertNull(t.scrambleDN((String) null));
    assertNull(t.scrambleDN((DN) null));
    t.scrambleDN("malformed");
  }



  /**
   * Provides basic test coverage for the translate method for an entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTranslateEntry()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final ScrambleAttributeTransformation t =
         new ScrambleAttributeTransformation(schema, 0L, true,
              Arrays.asList("description"), Arrays.asList("field1", "field2"));

    final Entry e = t.translate(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: foo"),
         0);

    assertNotNull(e);

    assertNotNull(e.getAttributeValue("description"));
    assertFalse(e.getAttributeValue("description").equals("foo"));
    assertEquals(e.getAttributeValue("description").length(), 3);
    assertTrue(e.getAttributeValue("description").matches("^[a-z][a-z][a-z]$"));
  }



  /**
   * Provides basic test coverage for the translateEntryToWrite method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTranslateEntryToWrite()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final ScrambleAttributeTransformation t =
         new ScrambleAttributeTransformation(schema, 0L, true,
              Arrays.asList("description"), Arrays.asList("field1", "field2"));

    final Entry e = t.translateEntryToWrite(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: foo"));

    assertNotNull(e);

    assertNotNull(e.getAttributeValue("description"));
    assertFalse(e.getAttributeValue("description").equals("foo"));
    assertEquals(e.getAttributeValue("description").length(), 3);
    assertTrue(e.getAttributeValue("description").matches("^[a-z][a-z][a-z]$"));
  }



  /**
   * Provides basic test coverage for the translate method for a change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTranslateChangeRecord()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final ScrambleAttributeTransformation t =
         new ScrambleAttributeTransformation(schema, 0L, true,
              Arrays.asList("description"), Arrays.asList("field1", "field2"));

    final LDIFAddChangeRecord r =
         (LDIFAddChangeRecord)
              t.translate(
                   new LDIFAddChangeRecord(new Entry(
                        "dn: dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: domain",
                        "dc: example",
                        "description: foo1BAR+bAz")),
                   0);

    assertNotNull(r);

    assertNotNull(r.getEntryToAdd().getAttributeValue("description"));
    assertFalse(r.getEntryToAdd().getAttributeValue("description").equals(
         "foo1BAR+bAz"));
    assertEquals(r.getEntryToAdd().getAttributeValue("description").length(),
         11);
    assertTrue(r.getEntryToAdd().getAttributeValue("description").matches(
         "^[a-z][a-z][a-z][0-9][A-Z][A-Z][A-Z]\\+[a-z][A-Z][a-z]$"));
  }



  /**
   * Provides basic test coverage for the translateChangeRecordToWrite method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTranslateChangeRecordToWrite()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final ScrambleAttributeTransformation t =
         new ScrambleAttributeTransformation(schema, 0L, true,
              Arrays.asList("description"), Arrays.asList("field1", "field2"));

    final LDIFAddChangeRecord r =
         (LDIFAddChangeRecord)
              t.translateChangeRecordToWrite(
                   new LDIFAddChangeRecord(new Entry(
                        "dn: dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: domain",
                        "dc: example",
                        "description: foo1BAR+bAz")));

    assertNotNull(r);

    assertNotNull(r.getEntryToAdd().getAttributeValue("description"));
    assertFalse(r.getEntryToAdd().getAttributeValue("description").equals(
         "foo1BAR+bAz"));
    assertEquals(r.getEntryToAdd().getAttributeValue("description").length(),
         11);
    assertTrue(r.getEntryToAdd().getAttributeValue("description").matches(
         "^[a-z][a-z][a-z][0-9][A-Z][A-Z][A-Z]\\+[a-z][A-Z][a-z]$"));
  }
}
