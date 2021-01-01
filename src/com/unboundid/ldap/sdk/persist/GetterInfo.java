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
import java.lang.reflect.Modifier;
import java.lang.reflect.Type;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.persist.PersistMessages.*;



/**
 * This class provides a data structure that holds information about an
 * annotated getter method.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetterInfo
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1578187843924054389L;



  // Indicates whether the associated method value should be included in the
  // entry created for an add operation.
  private final boolean includeInAdd;

  // Indicates whether the associated method value should be considered for
  // inclusion in the set of modifications used for modify operations.
  private final boolean includeInModify;

  // Indicates whether the associated method value is part of the RDN.
  private final boolean includeInRDN;

  // The class that contains the associated method.
  @NotNull private final Class<?> containingClass;

  // The filter usage for the associated method.
  @NotNull private final FilterUsage filterUsage;

  // The method with which this object is associated.
  @NotNull private final Method method;

  // The encoder used for this method.
  @NotNull private final ObjectEncoder encoder;

  // The name of the associated attribute type.
  @NotNull private final String attributeName;

  // The names of the object classes for the associated attribute.
  @NotNull private final String[] objectClasses;



  /**
   * Creates a new getter info object from the provided method.
   *
   * @param  m  The method to use to create this object.
   * @param  c  The class which holds the method.
   *
   * @throws  LDAPPersistException  If a problem occurs while processing the
   *                                given method.
   */
  GetterInfo(@NotNull final Method m, @NotNull final Class<?> c)
       throws LDAPPersistException
  {
    Validator.ensureNotNull(m, c);

    method = m;
    m.setAccessible(true);

    final LDAPGetter  a = m.getAnnotation(LDAPGetter.class);
    if (a == null)
    {
      throw new LDAPPersistException(ERR_GETTER_INFO_METHOD_NOT_ANNOTATED.get(
           m.getName(), c.getName()));
    }

    final LDAPObject o = c.getAnnotation(LDAPObject.class);
    if (o == null)
    {
      throw new LDAPPersistException(ERR_GETTER_INFO_CLASS_NOT_ANNOTATED.get(
           c.getName()));
    }

    containingClass = c;
    includeInRDN    = a.inRDN();
    includeInAdd    = (includeInRDN || a.inAdd());
    includeInModify = ((! includeInRDN) && a.inModify());
    filterUsage     = a.filterUsage();

    final int modifiers = m.getModifiers();
    if (Modifier.isStatic(modifiers))
    {
      throw new LDAPPersistException(ERR_GETTER_INFO_METHOD_STATIC.get(
           m.getName(), c.getName()));
    }

    final Type[] params = m.getGenericParameterTypes();
    if (params.length > 0)
    {
      throw new LDAPPersistException(ERR_GETTER_INFO_METHOD_TAKES_ARGUMENTS.get(
           m.getName(), c.getName()));
    }

    try
    {
      encoder = a.encoderClass().newInstance();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPPersistException(ERR_GETTER_INFO_CANNOT_GET_ENCODER.get(
           a.encoderClass().getName(), m.getName(), c.getName(),
           StaticUtils.getExceptionMessage(e)), e);
    }

    if (! encoder.supportsType(m.getGenericReturnType()))
    {
      throw new LDAPPersistException(
           ERR_GETTER_INFO_ENCODER_UNSUPPORTED_TYPE.get(
                encoder.getClass().getName(), m.getName(), c.getName(),
                String.valueOf(m.getGenericReturnType())));
    }

    final String structuralClass;
    if (o.structuralClass().isEmpty())
    {
      structuralClass = StaticUtils.getUnqualifiedClassName(c);
    }
    else
    {
      structuralClass = o.structuralClass();
    }

    final String[] ocs = a.objectClass();
    if ((ocs == null) || (ocs.length == 0))
    {
      objectClasses = new String[] { structuralClass };
    }
    else
    {
      objectClasses = ocs;
    }

    for (final String s : objectClasses)
    {
      if (! s.equalsIgnoreCase(structuralClass))
      {
        boolean found = false;
        for (final String oc : o.auxiliaryClass())
        {
          if (s.equalsIgnoreCase(oc))
          {
            found = true;
            break;
          }
        }

        if (! found)
        {
          throw new LDAPPersistException(ERR_GETTER_INFO_INVALID_OC.get(
               m.getName(), c.getName(), s));
        }
      }
    }

    final String attrName = a.attribute();
    if ((attrName == null) || attrName.isEmpty())
    {
      final String methodName = m.getName();
      if (methodName.startsWith("get") && (methodName.length() >= 4))
      {
        attributeName = StaticUtils.toInitialLowerCase(methodName.substring(3));
      }
      else
      {
        throw new LDAPPersistException(ERR_GETTER_INFO_CANNOT_INFER_ATTR.get(
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
   * Indicates whether the associated method value should be included in entries
   * generated for add operations.  Note that the value returned from this
   * method may be {@code true} even when the annotation has a value of
   * {@code false} if the associated field is to be included in entry RDNs.
   *
   * @return  {@code true} if the associated method value should be included in
   *          entries generated for add operations, or {@code false} if not.
   */
  public boolean includeInAdd()
  {
    return includeInAdd;
  }



  /**
   * Indicates whether the associated method value should be considered for
   * inclusion in the set of modifications generated for modify operations.
   * Note that the value returned from this method may be {@code false} even
   * when the annotation have a value of {@code true} if the associated field is
   * to be included in entry RDNs.
   *
   * @return  {@code true} if the associated method value should be considered
   *          for inclusion in the set of modifications generated for modify
   *          operations, or {@code false} if not.
   */
  public boolean includeInModify()
  {
    return includeInModify;
  }



  /**
   * Indicates whether the associated method value should be used to generate
   * entry RDNs.
   *
   * @return  {@code true} if the associated method value should be used to
   *          generate entry RDNs, or {@code false} if not.
   */
  public boolean includeInRDN()
  {
    return includeInRDN;
  }



  /**
   * Retrieves the filter usage for the associated method.
   *
   * @return  The filter usage for the associated method.
   */
  @NotNull()
  public FilterUsage getFilterUsage()
  {
    return filterUsage;
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
   * Retrieves the names of the object classes containing the associated
   * attribute.
   *
   * @return  The names of the object classes containing the associated
   *          attribute.
   */
  @NotNull()
  public String[] getObjectClasses()
  {
    return objectClasses;
  }



  /**
   * Constructs a definition for an LDAP attribute type which may be added to
   * the directory server schema to allow it to hold the value of the associated
   * method.  Note that the object identifier used for the constructed attribute
   * type definition is not required to be valid or unique.
   *
   * @return  The constructed attribute type definition.
   *
   * @throws  LDAPPersistException  If the object encoder does not support
   *                                encoding values for the associated field
   *                                type.
   */
  @NotNull()
  AttributeTypeDefinition constructAttributeType()
       throws LDAPPersistException
  {
    return constructAttributeType(DefaultOIDAllocator.getInstance());
  }



  /**
   * Constructs a definition for an LDAP attribute type which may be added to
   * the directory server schema to allow it to hold the value of the associated
   * method.  Note that the object identifier used for the constructed attribute
   * type definition is not required to be valid or unique.
   *
   * @param  a  The OID allocator to use to generate the object identifier.  It
   *            must not be {@code null}.
   *
   * @return  The constructed attribute type definition.
   *
   * @throws  LDAPPersistException  If the object encoder does not support
   *                                encoding values for the associated method
   *                                type.
   */
  @NotNull()
  AttributeTypeDefinition constructAttributeType(@NotNull final OIDAllocator a)
       throws LDAPPersistException
  {
    return encoder.constructAttributeType(method, a);
  }



  /**
   * Creates an attribute with the value returned by invoking the associated
   * method on the provided object.
   *
   * @param  o  The object for which to invoke the associated method.
   *
   * @return  The attribute containing the encoded representation of the method
   *          value, or {@code null} if the method returned {@code null}.
   *
   * @throws  LDAPPersistException  If a problem occurs while encoding the
   *                                value of the associated field for the
   *                                provided object.
   */
  @Nullable()
  Attribute encode(@NotNull final Object o)
            throws LDAPPersistException
  {
    try
    {
      final Object methodValue = method.invoke(o);
      if (methodValue == null)
      {
        return null;
      }

      return encoder.encodeMethodValue(method, methodValue, attributeName);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPPersistException(
           ERR_GETTER_INFO_CANNOT_ENCODE.get(method.getName(),
                containingClass.getName(), StaticUtils.getExceptionMessage(e)),
           e);
    }
  }
}
