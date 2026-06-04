/*
 * Copyright 2026 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2026 Ping Identity Corporation
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
 * Copyright (C) 2026 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.persist;



import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPRequest;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.unboundidds.controls.GetServerIDResponseControl;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases to ensure that the
 * {@code DefaultObjectEncoderWhitelistingObjectInputStream} behaves as
 * expected.
 */
public final class DefaultObjectEncoderWhitelistingObjectInputStreamTestCase
       extends LDAPSDKTestCase
{
  /**
   * Serializes and attempts to deserialize the provided object using the
   * specified allowed class.
   *
   * @param  object         The object to serialize and attempt to deserialize.
   * @param  allowedClass   The allowed class to use for the object input
   *                        stream.
   * @param  expectAllowed  Indicates whether the deserialization attempt is
   *                        expected to succeed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "deserializationTestObjects")
  public void testDeserialization(final Serializable object,
                                  final Class<?> allowedClass,
                                  final boolean expectAllowed)
         throws Exception
  {
    // Serialize the object.
    final byte[] serializedObjectBytes;
    try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
         final ObjectOutputStream oos = new ObjectOutputStream(baos))
    {
      oos.writeObject(object);
      oos.flush();
      serializedObjectBytes = baos.toByteArray();
    }


    // Attempt to deserialize the object.
    try (final ByteArrayInputStream bais =
              new ByteArrayInputStream(serializedObjectBytes);
         final DefaultObjectEncoderWhitelistingObjectInputStream doewois =
              new DefaultObjectEncoderWhitelistingObjectInputStream(bais,
                   allowedClass))
    {
      final Object deserializedObject = doewois.readObject();
      assertTrue(expectAllowed);
      assertEquals(deserializedObject.getClass(), object.getClass());
    }
    catch (final SecurityException e)
    {
      assertFalse(expectAllowed,
           StaticUtils.getExceptionMessage(e));
    }
  }



  /**
   * Serializes and attempts to deserialize the provided object using the
   * specified allowed class when filtering is disabled via a system property.
   *
   * @param  object         The object to serialize and attempt to deserialize.
   * @param  allowedClass   The allowed class to use for the object input
   *                        stream.
   * @param  expectAllowed  Indicates whether the deserialization attempt is
   *                        expected to succeed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "deserializationTestObjects")
  public void testDeserializationFilteringDisabled(final Serializable object,
                                                   final Class<?> allowedClass,
                                                   final boolean expectAllowed)
         throws Exception
  {
    try
    {
      System.setProperty(
           DefaultObjectEncoderWhitelistingObjectInputStream.
                PROPERTY_DISABLE_DESERIALIZATION_FILTER,
           "true");

      // Serialize the object.
      final byte[] serializedObjectBytes;
      try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
           final ObjectOutputStream oos = new ObjectOutputStream(baos))
      {
        oos.writeObject(object);
        oos.flush();
        serializedObjectBytes = baos.toByteArray();
      }


      // Attempt to deserialize the object.
      try (final ByteArrayInputStream bais =
                new ByteArrayInputStream(serializedObjectBytes);
           final DefaultObjectEncoderWhitelistingObjectInputStream doewois =
                new DefaultObjectEncoderWhitelistingObjectInputStream(bais,
                     allowedClass))
      {
        final Object deserializedObject = doewois.readObject();
        assertEquals(deserializedObject.getClass(), object.getClass());
      }
    }
    finally
    {
      System.clearProperty(
           DefaultObjectEncoderWhitelistingObjectInputStream.
                PROPERTY_DISABLE_DESERIALIZATION_FILTER);
    }
  }



  /**
   * Retrieves a set of data for use in deserialization testing.
   *
   * @return  A set of data for use in deserialization testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name = "deserializationTestObjects")
  public Object[][] getDeserializationTestObjects()
         throws Exception
  {
    return new Object[][]
    {
      // Test when trying to deserialize a filter when expecting a filter.
      new Object[]
      {
        Filter.equals("uid", "jdoe"),
        Filter.class,
        true
      },

      // Test when trying to deserialize a filter when expecting a DN.
      new Object[]
      {
        Filter.equals("uid", "jdoe"),
        DN.class,
        false
      },

      // Test when trying to deserialize a simple bind request when expecting a
      // simple bind request.
      new Object[]
      {
        new SimpleBindRequest("cn=Directory Manager", "password"),
        SimpleBindRequest.class,
        true
      },

      // Test when trying to deserialize a simple bind request when expecting a
      // BindRequest, which is the immediate superclass.
      new Object[]
      {
        new SimpleBindRequest("cn=Directory Manager", "password"),
        BindRequest.class,
        true
      },

      // Test when trying to deserialize a simple bind request when expecting an
      // LDAPRequest, which is a higher-up ancestor.
      new Object[]
      {
        new SimpleBindRequest("cn=Directory Manager", "password"),
        LDAPRequest.class,
        true
      },

      // Test when trying to deserialize a get server ID response control when
      // expecting a get server ID response control
      new Object[]
      {
        new GetServerIDResponseControl("foo"),
        GetServerIDResponseControl.class,
        true
      },

      // Test when trying to deserialize a get server ID response control when
      // expecting a DecodeableControl, which is an interface that the get
      // server ID response control implements.
      new Object[]
      {
        new GetServerIDResponseControl("foo"),
        DecodeableControl.class,
        true
      }
    };
  }
}
