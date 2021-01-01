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
package com.unboundid.util.json;



import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Iterator;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the JSON object reader class.
 */
public final class JSONObjectReaderTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the ability to read from an input stream that doesn't contain any
   * data.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReaderEmptyStream()
         throws Exception
  {
    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(new byte[0]);

    final JSONObjectReader reader = new JSONObjectReader(inputStream);

    assertNull(reader.readObject());

    reader.close();
  }



  /**
   * Tests the ability to read from an input stream that contains only spaces.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReaderStreamWithOnlySpaces()
         throws Exception
  {
    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream("     ".getBytes("UTF-8"));

    final JSONObjectReader reader = new JSONObjectReader(inputStream);

    assertNull(reader.readObject());

    reader.close();
  }



  /**
   * Tests the ability to read from an input stream that contains only a single
   * newline.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReaderStreamWithOnlyNewline()
         throws Exception
  {
    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream("\n".getBytes("UTF-8"));

    final JSONObjectReader reader = new JSONObjectReader(inputStream);

    assertNull(reader.readObject());

    reader.close();
  }



  /**
   * Tests the ability to read from an input stream that contains only
   * whitespace.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReaderStreamWithOnlyWhitespace()
         throws Exception
  {
    final String whitespace =
         "\n" +
         "\r\n" +
         "// This is a comment that extends until the end of the line.\n" +
         "# This is also a comment that extends until the end of the line.\n" +
         "/* This is another comment */ # Followed by end-of-line comment\n" +
         "\n" +
         "\n" +
         "# Ends with a comment.";

    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(whitespace.getBytes("UTF-8"));

    final JSONObjectReader reader = new JSONObjectReader(inputStream);

    assertNull(reader.readObject());

    reader.close();
  }



  /**
   * Tests the ability to read a JSON object from an input stream that only
   * contains that one object.
   *
   * @param  s  The string to be decoded.
   * @param  o  A JSON object that is equal to the one expected to be decoded.
   * @param  n  The expected normalized string representation of the object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="validObjectStrings")
  public void testReadSingleObject(final String s, final JSONObject o,
                                   final String n)
         throws Exception
  {
    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(s.getBytes("UTF-8"));

    final JSONObjectReader reader = new JSONObjectReader(inputStream);

    final JSONObject readObject = reader.readObject();
    assertEquals(readObject, o);

    assertEquals(readObject.toNormalizedString(), n);

    assertNull(reader.readObject());

    reader.close();
  }



  /**
   * Tests the ability to read multiple JSON objects from an input stream when
   * no separators are used between them.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testDecodeMultipleObjectsNoSeparators()
         throws Exception
  {
    final ArrayList<JSONObject> expectedObjects = new ArrayList<JSONObject>(10);
    final ArrayList<String> expectedNormalizedStrings =
         new ArrayList<String>(10);

    final StringBuilder buffer = new StringBuilder();
    final Iterator<Object[]> dataProviderIterator = getValidObjectStrings();
    while (dataProviderIterator.hasNext())
    {
      final Object[] o = dataProviderIterator.next();

      buffer.append((String) o[0]);

      expectedObjects.add((JSONObject) o[1]);

      expectedNormalizedStrings.add((String) o[2]);
    }

    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(buffer.toString().getBytes("UTF-8"));

    final JSONObjectReader reader = new JSONObjectReader(inputStream);

    final Iterator<JSONObject> objectIterator = expectedObjects.iterator();
    final Iterator<String> normalizedStringIterator =
         expectedNormalizedStrings.iterator();
    while (objectIterator.hasNext())
    {
      final JSONObject readObject = reader.readObject();
      assertNotNull(readObject);

      final JSONObject expectedObject = objectIterator.next();
      assertEquals(readObject, expectedObject);

      final String expectedNormalizedString = normalizedStringIterator.next();
      assertEquals(readObject.toNormalizedString(), expectedNormalizedString);
    }

    assertNull(reader.readObject());

    reader.close();
  }



  /**
   * Tests the ability to read multiple JSON objects from an input stream when
   * a single space is added between each object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testDecodeMultipleObjectsSingleSpaceSeparator()
         throws Exception
  {
    final ArrayList<JSONObject> expectedObjects = new ArrayList<JSONObject>(10);
    final ArrayList<String> expectedNormalizedStrings =
         new ArrayList<String>(10);

    final StringBuilder buffer = new StringBuilder();
    final Iterator<Object[]> dataProviderIterator = getValidObjectStrings();
    while (dataProviderIterator.hasNext())
    {
      final Object[] o = dataProviderIterator.next();

      buffer.append((String) o[0]);
      buffer.append(' ');

      expectedObjects.add((JSONObject) o[1]);

      expectedNormalizedStrings.add((String) o[2]);
    }

    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(buffer.toString().getBytes("UTF-8"));

    final JSONObjectReader reader = new JSONObjectReader(inputStream);

    final Iterator<JSONObject> objectIterator = expectedObjects.iterator();
    final Iterator<String> normalizedStringIterator =
         expectedNormalizedStrings.iterator();
    while (objectIterator.hasNext())
    {
      final JSONObject readObject = reader.readObject();
      assertNotNull(readObject);

      final JSONObject expectedObject = objectIterator.next();
      assertEquals(readObject, expectedObject);

      final String expectedNormalizedString = normalizedStringIterator.next();
      assertEquals(readObject.toNormalizedString(), expectedNormalizedString);
    }

    assertNull(reader.readObject());

    reader.close();
  }



  /**
   * Tests the ability to read multiple JSON objects from an input stream when
   * a single line break is added between each object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testDecodeMultipleObjectsSingleNewlineSeparator()
         throws Exception
  {
    final ArrayList<JSONObject> expectedObjects = new ArrayList<JSONObject>(10);
    final ArrayList<String> expectedNormalizedStrings =
         new ArrayList<String>(10);

    final StringBuilder buffer = new StringBuilder();
    final Iterator<Object[]> dataProviderIterator = getValidObjectStrings();
    while (dataProviderIterator.hasNext())
    {
      final Object[] o = dataProviderIterator.next();

      buffer.append((String) o[0]);
      buffer.append('\n');

      expectedObjects.add((JSONObject) o[1]);

      expectedNormalizedStrings.add((String) o[2]);
    }

    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(buffer.toString().getBytes("UTF-8"));

    final JSONObjectReader reader = new JSONObjectReader(inputStream);

    final Iterator<JSONObject> objectIterator = expectedObjects.iterator();
    final Iterator<String> normalizedStringIterator =
         expectedNormalizedStrings.iterator();
    while (objectIterator.hasNext())
    {
      final JSONObject readObject = reader.readObject();
      assertNotNull(readObject);

      final JSONObject expectedObject = objectIterator.next();
      assertEquals(readObject, expectedObject);

      final String expectedNormalizedString = normalizedStringIterator.next();
      assertEquals(readObject.toNormalizedString(), expectedNormalizedString);
    }

    assertNull(reader.readObject());

    reader.close();
  }



  /**
   * Tests the ability to read multiple JSON objects from an input stream when
   * a line break, an empty line, and a line containing a comment is added
   * between each object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testDecodeMultipleObjectsCommentSeparator()
         throws Exception
  {
    final ArrayList<JSONObject> expectedObjects = new ArrayList<JSONObject>(10);
    final ArrayList<String> expectedNormalizedStrings =
         new ArrayList<String>(10);

    final StringBuilder buffer = new StringBuilder();
    final Iterator<Object[]> dataProviderIterator = getValidObjectStrings();
    while (dataProviderIterator.hasNext())
    {
      final Object[] o = dataProviderIterator.next();

      buffer.append("\n\r\n#This is a comment\n");
      buffer.append((String) o[0]);

      expectedObjects.add((JSONObject) o[1]);

      expectedNormalizedStrings.add((String) o[2]);
    }

    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(buffer.toString().getBytes("UTF-8"));

    final JSONObjectReader reader = new JSONObjectReader(inputStream);

    final Iterator<JSONObject> objectIterator = expectedObjects.iterator();
    final Iterator<String> normalizedStringIterator =
         expectedNormalizedStrings.iterator();
    while (objectIterator.hasNext())
    {
      final JSONObject readObject = reader.readObject();
      assertNotNull(readObject);

      final JSONObject expectedObject = objectIterator.next();
      assertEquals(readObject, expectedObject);

      final String expectedNormalizedString = normalizedStringIterator.next();
      assertEquals(readObject.toNormalizedString(), expectedNormalizedString);
    }

    assertNull(reader.readObject());

    reader.close();
  }



  /**
   * Tests the behavior when reading an invalid JSON object.
   *
   * @param  s  The string to be decoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="invalidObjectStrings",
        expectedExceptions = { JSONException.class })
  public void testReadInvalidObject(final String s)
         throws Exception
  {
    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(s.getBytes("UTF-8"));

    final JSONObjectReader reader = new JSONObjectReader(inputStream);

    try
    {
      if (reader.readObject() == null)
      {
        // This is actually fine, but the JSONObject constructor that takes a
        // string doesn't allow empty objects so it's considered invalid for
        // that.  Since we're using the JSONObject test data, we'll throw an
        // exception to simulate that behavior.
        throw new JSONException("Read from a stream with no objects");
      }

      if (reader.readObject() != null)
      {
        // This is also fine, but the JSONObject constructor that takes a
        // string doesn't allow multiple objects so we'll throw an exception for
        // this, too.
        throw new JSONException("Read from a stream with multiple objects");
      }
    }
    finally
    {
      reader.close();
    }
  }



  /**
   * Retrieves a set of test data that can be used to test the ability to decode
   * valid JSON strings to their corresponding objects.
   *
   * @return  A set of test data that can be used to test the ability to decode
   *          valid JSON strings to their corresponding objects.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="validObjectStrings")
  public Iterator<Object[]> getValidObjectStrings()
         throws Exception
  {
    return new JSONObjectTestCase().getValidObjectStrings();
  }



  /**
   * Retrieves a set of test data that can be used to verify that the JSON
   * parser will properly reject strings that cannot be parsed as JSON objects.
   *
   * @return  A set of test data that can be used to verify that the JSON parser
   *          will properly reject strings that cannot be parsed as JSON
   *          objects.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="invalidObjectStrings")
  public Object[][] getInvalidObjectStrings()
         throws Exception
  {
    return new JSONObjectTestCase().getInvalidObjectStrings();
  }
}
