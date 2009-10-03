/*
 * Copyright 2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009 UnboundID Corp.
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



import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.util.Extensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an API for converting between Java object fields and LDAP
 * attributes.  Concrete instances of this class must provide a default
 * zero-argument constructor.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class LDAPFieldEncoder
       implements Serializable
{
  /**
   * Indicates whether this LDAP field encoder may be used to encode or decode
   * objects of the specified type.
   *
   * @param  t  The type of object for which to make the determination.
   *
   * @return  {@code true} if this LDAP field encoder may be used for objects of
   *          the specified type, or {@code false} if not.
   */
  public abstract boolean supportsType(final Class<?> t);



  /**
   * Constructs a definition for an LDAP attribute type which may be added to
   * the directory server schema to allow it to hold the value of the specified
   * field.  Note that the object identifier used for the constructed attribute
   * type definition is not required to be valid or unique.
   *
   * @param  f  The field for which to construct an LDAP attribute type
   *            definition.  It will include the {@link LDAPField} annotation
   *            type.
   *
   * @return  The constructed attribute type definition.
   *
   * @throws  LDAPPersistException  If this LDAP field encoder does not support
   *                                encoding values for the associated field
   *                                type.
   */
  public final AttributeTypeDefinition constructAttributeType(final Field f)
         throws LDAPPersistException
  {
    return constructAttributeType(f, DefaultOIDAllocator.getInstance());
  }



  /**
   * Constructs a definition for an LDAP attribute type which may be added to
   * the directory server schema to allow it to hold the value of the specified
   * field.
   *
   * @param  f  The field for which to construct an LDAP attribute type
   *            definition.  It will include the {@link LDAPField} annotation
   *            type.
   * @param  a  The OID allocator to use to generate the object identifier.  It
   *            must not be {@code null}.
   *
   * @return  The constructed attribute type definition.
   *
   * @throws  LDAPPersistException  If this LDAP field encoder does not support
   *                                encoding values for the associated field
   *                                type.
   */
  public abstract AttributeTypeDefinition constructAttributeType(final Field f,
                                               final OIDAllocator a)
         throws LDAPPersistException;



  /**
   * Constructs a definition for an LDAP attribute type which may be added to
   * the directory server schema to allow it to hold the value returned by the
   * specified method.  Note that the object identifier used for the constructed
   * attribute type definition is not required to be valid or unique.
   *
   * @param  m  The method for which to construct an LDAP attribute type
   *            definition.  It will include the {@link LDAPFieldGetter}
   *            annotation type.
   *
   * @return  The constructed attribute type definition.
   *
   * @throws  LDAPPersistException  If this LDAP field encoder does not support
   *                                encoding values for the associated method
   *                                type.
   */
  public final AttributeTypeDefinition constructAttributeType(final Method m)
         throws LDAPPersistException
  {
    return constructAttributeType(m, DefaultOIDAllocator.getInstance());
  }



  /**
   * Constructs a definition for an LDAP attribute type which may be added to
   * the directory server schema to allow it to hold the value returned by the
   * specified method.  Note that the object identifier used for the constructed
   * attribute type definition is not required to be valid or unique.
   *
   * @param  m  The method for which to construct an LDAP attribute type
   *            definition.  It will include the {@link LDAPFieldGetter}
   *            annotation type.
   * @param  a  The OID allocator to use to generate the object identifier.  It
   *            must not be {@code null}.
   *
   * @return  The constructed attribute type definition.
   *
   * @throws  LDAPPersistException  If this LDAP field encoder does not support
   *                                encoding values for the associated method
   *                                type.
   */
  public abstract AttributeTypeDefinition constructAttributeType(final Method m,
                                               final OIDAllocator a)
         throws LDAPPersistException;



  /**
   * Encodes the provided field to an LDAP attribute.
   *
   * @param  field  The field to be encoded.
   * @param  value  The value for the field in the object to be encoded.
   * @param  name   The name to use for the constructed attribute.
   *
   * @return  The attribute containing the encoded representation of the
   *          provided field.
   *
   * @throws  LDAPPersistException  If a problem occurs while attempting to
   *                                construct an attribute for the field.
   */
  public abstract Attribute encodeFieldValue(final Field field,
                                             final Object value,
                                             final String name)
         throws LDAPPersistException;



  /**
   * Encodes the provided method to an LDAP attribute.
   *
   * @param  method  The method to be encoded.
   * @param  value   The value returned by the method in the object to be
   *                 encoded.
   * @param  name    The name to use for the constructed attribute.
   *
   * @return  The attribute containing the encoded representation of the
   *          provided method value.
   *
   * @throws  LDAPPersistException  If a problem occurs while attempting to
   *                                construct an attribute for the method.
   */
  public abstract Attribute encodeMethodValue(final Method method,
                                              final Object value,
                                              final String name)
         throws LDAPPersistException;



  /**
   * Updates the provided object to assign a value for the specified field from
   * the contents of the given attribute.
   *
   * @param  field      The field to update in the provided object.
   * @param  object     The object to be updated.
   * @param  attribute  The attribute whose value(s) should be used to update
   *                    the specified field in the given object.
   *
   * @throws  LDAPPersistException  If a problem occurs while attempting to
   *                                assign a value to the specified field.
   */
  public abstract void decodeField(final Field field, final Object object,
                                   final Attribute attribute)
         throws LDAPPersistException;



  /**
   * Updates the provided object to invoke the specified method to set a value
   * from the contents of the given attribute.
   *
   * @param  method     The method to invoke in the provided object.
   * @param  object     The object to be updated.
   * @param  attribute  The attribute whose value(s) should be used to update
   *                    the specified method in the given object.
   *
   * @throws  LDAPPersistException  If a problem occurs while attempting to
   *                                determine the value or invoke the specified
   *                                method.
   */
  public abstract void invokeSetter(final Method method, final Object object,
                                    final Attribute attribute)
         throws LDAPPersistException;
}
