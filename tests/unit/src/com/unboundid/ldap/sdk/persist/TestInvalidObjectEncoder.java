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
package com.unboundid.ldap.sdk.persist;



import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Type;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;



/**
 * This class provides an implementation of an object encoder that will throw
 * an exception whenever it is instantiated.
 */
public class TestInvalidObjectEncoder
       extends ObjectEncoder
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -950250504084738271L;



  /**
   * Creates a new instance of this class.  This method will always throw a
   * runtime exception.
   */
  public TestInvalidObjectEncoder()
  {
    throw new RuntimeException();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsType(final Type t)
  {
    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public AttributeTypeDefinition constructAttributeType(final Field f,
                                                        final OIDAllocator a)
         throws LDAPPersistException
  {
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public AttributeTypeDefinition constructAttributeType(final Method m,
                                                        final OIDAllocator a)
         throws LDAPPersistException
  {
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsMultipleValues(final Field field)
  {
    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsMultipleValues(final Method method)
  {
    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Attribute encodeFieldValue(final Field field, final Object value,
                                    final String name)
         throws LDAPPersistException
  {
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Attribute encodeMethodValue(final Method method, final Object value,
                                     final String name)
         throws LDAPPersistException
  {
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void decodeField(final Field field, final Object object,
                          final Attribute attribute)
         throws LDAPPersistException
  {
    // No implementation required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void invokeSetter(final Method method, final Object object,
                           final Attribute attribute)
         throws LDAPPersistException
  {
    // No implementation required.
  }
}
