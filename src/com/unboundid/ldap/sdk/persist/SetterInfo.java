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



import java.io.Serializable;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.util.List;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.persist.PersistMessages.*;



/**
 * This class provides a data structure that holds information about an
 * annotated setter method.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SetterInfo
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1743750276508505946L;



  // Indicates whether attempts to invoke the associated method should fail if
  // the LDAP attribute has a value that is not valid for the data type of the
  // method argument.
  private final boolean failOnInvalidValue;

  // Indicates whether attempts to invoke the associated method should fail if
  // the LDAP attribute has multiple values but the method argument can only
  // hold a single value.
  private final boolean failOnTooManyValues;

  // Indicates whether the associated method takes an argument that supports
  // multiple values.
  private final boolean supportsMultipleValues;

  // The class that contains the associated method.
  @NotNull private final Class<?> containingClass;

  // The method with which this object is associated.
  @NotNull private final Method method;

  // The encoder used for this method.
  @NotNull private final ObjectEncoder encoder;

  // The name of the associated attribute type.
  @NotNull private final String attributeName;



  /**
   * Creates a new setter info object from the provided method.
   *
   * @param  m  The method to use to create this object.
   * @param  c  The class which holds the method.
   *
   * @throws  LDAPPersistException  If a problem occurs while processing the
   *                                given method.
   */
  SetterInfo(@NotNull final Method m, @NotNull final Class<?> c)
       throws LDAPPersistException
  {
    Validator.ensureNotNull(m, c);

    method = m;
    m.setAccessible(true);

    final LDAPSetter  a = m.getAnnotation(LDAPSetter.class);
    if (a == null)
    {
      throw new LDAPPersistException(ERR_SETTER_INFO_METHOD_NOT_ANNOTATED.get(
           m.getName(), c.getName()));
    }

    final LDAPObject o = c.getAnnotation(LDAPObject.class);
    if (o == null)
    {
      throw new LDAPPersistException(ERR_SETTER_INFO_CLASS_NOT_ANNOTATED.get(
           c.getName()));
    }

    containingClass    = c;
    failOnInvalidValue = a.failOnInvalidValue();

    final Type[] params = m.getGenericParameterTypes();
    if (params.length != 1)
    {
      throw new LDAPPersistException(
           ERR_SETTER_INFO_METHOD_DOES_NOT_TAKE_ONE_ARGUMENT.get(m.getName(),
                c.getName()));
    }

    try
    {
      encoder = a.encoderClass().newInstance();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPPersistException(
           ERR_SETTER_INFO_CANNOT_GET_ENCODER.get(a.encoderClass().getName(),
                m.getName(), c.getName(), StaticUtils.getExceptionMessage(e)),
           e);
    }

    if (! encoder.supportsType(params[0]))
    {
      throw new LDAPPersistException(
           ERR_SETTER_INFO_ENCODER_UNSUPPORTED_TYPE.get(
                encoder.getClass().getName(), m.getName(), c.getName(),
                String.valueOf(params[0])));
    }

    supportsMultipleValues = encoder.supportsMultipleValues(m);
    if (supportsMultipleValues)
    {
      failOnTooManyValues = false;
    }
    else
    {
      failOnTooManyValues = a.failOnTooManyValues();
    }

    final String attrName = a.attribute();
    if ((attrName == null) || attrName.isEmpty())
    {
      final String methodName = m.getName();
      if (methodName.startsWith("set") && (methodName.length() >= 4))
      {
        attributeName = StaticUtils.toInitialLowerCase(methodName.substring(3));
      }
      else
      {
        throw new LDAPPersistException(ERR_SETTER_INFO_CANNOT_INFER_ATTR.get(
             methodName, c.getName()));
      }
    }
    else
    {
      attributeName = attrName;
    }
  }



  /**
   * Retrieves the method with which this object is associated.
   *
   * @return  The method with which this object is associated.
   */
  @NotNull()
  public Method getMethod()
  {
    return method;
  }



  /**
   * Retrieves the class that is marked with the {@link LDAPObject} annotation
   * and contains the associated field.
   *
   * @return  The class that contains the associated field.
   */
  @NotNull()
  public Class<?> getContainingClass()
  {
    return containingClass;
  }



  /**
   * Indicates whether attempts to initialize an object should fail if the LDAP
   * attribute has a value that cannot be represented in the argument type for
   * the associated method.
   *
   * @return  {@code true} if an exception should be thrown if an LDAP attribute
   *          has a value that cannot be provided as an argument to the
   *          associated method, or {@code false} if the method should not be
   *          invoked.
   */
  public boolean failOnInvalidValue()
  {
    return failOnInvalidValue;
  }



  /**
   * Indicates whether attempts to initialize an object should fail if the
   * LDAP attribute has multiple values but the associated method argument can
   * only hold a single value.  Note that the value returned from this method
   * may be {@code false} even when the annotation has a value of {@code true}
   * if the associated method takes an argument that supports multiple values.
   *
   * @return  {@code true} if an exception should be thrown if an attribute has
   *          too many values to provide to the associated method, or
   *          {@code false} if the first value returned should be provided as an
   *          argument to the associated method.
   */
  public boolean failOnTooManyValues()
  {
    return failOnTooManyValues;
  }



  /**
   * Retrieves the encoder that should be used for the associated method.
   *
   * @return  The encoder that should be used for the associated method.
   */
  @NotNull()
  public ObjectEncoder getEncoder()
  {
    return encoder;
  }



  /**
   * Retrieves the name of the LDAP attribute used to hold values for the
   * associated method.
   *
   * @return  The name of the LDAP attribute used to hold values for the
   *          associated method.
   */
  @NotNull()
  public String getAttributeName()
  {
    return attributeName;
  }



  /**
   * Indicates whether the associated method takes an argument that can hold
   * multiple values.
   *
   * @return  {@code true} if the associated method takes an argument that can
   *          hold multiple values, or {@code false} if not.
   */
  public boolean supportsMultipleValues()
  {
    return supportsMultipleValues;
  }



  /**
   * Invokes the setter method on the provided object with the value from the
   * given attribute.
   *
   * @param  o               The object for which to invoke the setter method.
   * @param  e               The entry being decoded.
   * @param  failureReasons  A list to which information about any failures
   *                         may be appended.
   *
   * @return  {@code true} if the decode process was completely successful, or
   *          {@code false} if there were one or more failures.
   */
  boolean invokeSetter(@NotNull final Object o, @NotNull final Entry e,
                       @NotNull final List<String> failureReasons)
  {
    boolean successful = true;

    final Attribute a = e.getAttribute(attributeName);
    if ((a == null) || (! a.hasValue()))
    {
      try
      {
        encoder.setNull(method, o);
      }
      catch (final LDAPPersistException lpe)
      {
        Debug.debugException(lpe);
        successful = false;
        failureReasons.add(lpe.getMessage());
      }

      return successful;
    }

    if (failOnTooManyValues && (a.size() > 1))
    {
      successful = false;
      failureReasons.add(ERR_SETTER_INFO_METHOD_NOT_MULTIVALUED.get(
           method.getName(), a.getName(), containingClass.getName()));
    }

    try
    {
      encoder.invokeSetter(method, o, a);
    }
    catch (final LDAPPersistException lpe)
    {
      Debug.debugException(lpe);
      if (failOnInvalidValue)
      {
        successful = false;
        failureReasons.add(lpe.getMessage());
      }
    }

    return successful;
  }
}
