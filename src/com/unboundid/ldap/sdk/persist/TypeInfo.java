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



import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.List;
import java.util.Set;

import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;



/**
 * This class is a simple data structure that holds information about a Java
 * type that may be used in conjunction with the LDAP SDK persistence framework.
 * Note, however, that it does not support all forms of Type objects.  It
 * supports all {@code Class} objects, and it supports {@code ParameterizedType}
 * objects in which there is a single actual type argument and both the raw and
 * actual type arguments are {@code Class} objects.  It does not support other
 * kinds of {@code Type} objects.
 */
final class TypeInfo
{
  // Indicates whether this type represents an array.
  private final boolean isArray;

  // Indicates whether this type represents an enum.
  private final boolean isEnum;

  // Indicates whether this type represents a list.
  private final boolean isList;

  // Indicates whether this type represents a set.
  private final boolean isSet;

  // Indicates whether the associated type is supported.
  private final boolean isSupported;

  // The base class for the associated type.  For a Class object, it will simply
  // be the associated class.  For a parameterized type object, it will be the
  // raw type class.
  @Nullable private final Class<?> baseClass;

  // The component type for the associated type.  This will only be set for
  // array, list, and set objects, and it will specify the type of object that
  // can be held in that array, list, or set.
  @Nullable private final Class<?> componentType;

  // The type used to create this object.
  @NotNull private final Type type;



  /**
   * Creates a new instance of this object with the specified type.
   *
   * @param  type  The type to use to create this object.  It must not be
   *               {@code null}.
   */
  TypeInfo(@NotNull final Type type)
  {
    this.type = type;

    if (type instanceof Class)
    {
      isSupported = true;
      baseClass   = (Class<?>) type;
      isArray     = baseClass.isArray();
      isEnum      = baseClass.isEnum();

      if (isArray)
      {
        componentType = baseClass.getComponentType();
        isList        = false;
        isSet         = false;
      }
      else if (List.class.isAssignableFrom(baseClass))
      {
        componentType = Object.class;
        isList        = true;
        isSet         = false;
      }
      else if (Set.class.isAssignableFrom(baseClass))
      {
        componentType = Object.class;
        isList        = false;
        isSet         = true;
      }
      else
      {
        componentType = null;
        isList        = false;
        isSet         = false;
      }
    }
    else if (type instanceof ParameterizedType)
    {
      final ParameterizedType pt         = (ParameterizedType) type;
      final Type              rawType    = pt.getRawType();
      final Type[]            typeParams = pt.getActualTypeArguments();
      if ((rawType instanceof Class) && (typeParams.length == 1) &&
          (typeParams[0] instanceof Class))
      {
        baseClass     = (Class<?>) rawType;
        componentType = (Class<?>) typeParams[0];

        if (List.class.isAssignableFrom(baseClass))
        {
          isSupported = true;
          isArray     = false;
          isEnum      = false;
          isList      = true;
          isSet       = false;
        }
        else if (Set.class.isAssignableFrom(baseClass))
        {
          isSupported = true;
          isArray     = false;
          isEnum      = false;
          isList      = false;
          isSet       = true;
        }
        else
        {
          isSupported = false;
          isArray     = false;
          isEnum      = false;
          isList      = false;
          isSet       = false;
        }
      }
      else
      {
        isSupported   = false;
        isArray       = false;
        isEnum        = false;
        isList        = false;
        isSet         = false;
        baseClass     = null;
        componentType = null;
      }
    }
    else
    {
      isSupported   = false;
      isArray       = false;
      isEnum        = false;
      isList        = false;
      isSet         = false;
      baseClass     = null;
      componentType = null;
    }
  }



  /**
   * Retrieves the type used to create this object.
   *
   * @return  The type used to create this object.
   */
  @NotNull()
  public Type getType()
  {
    return type;
  }



  /**
   * Indicates whether the provided type is supported by this class.
   *
   * @return  {@code true} if the provided type is supported by this class, or
   *          {@code false} if not.
   */
  public boolean isSupported()
  {
    return isSupported;
  }



  /**
   * Retrieves the base class for the associated type.
   *
   * @return  The base class for the associated type, or {@code null} if the
   *          type is not supported.
   */
  @Nullable()
  public Class<?> getBaseClass()
  {
    return baseClass;
  }



  /**
   * Retrieves the component type for the associated type, if applicable.
   *
   * @return  The component type for the associated type, or {@code null} if
   *          there is none.
   */
  @Nullable()
  public Class<?> getComponentType()
  {
    return componentType;
  }



  /**
   * Indicates whether the provided type represents an array.
   *
   * @return  {@code true} if the provided type represents an array, or
   *          {@code false} if not.
   */
  public boolean isArray()
  {
    return isArray;
  }



  /**
   * Indicates whether the provided type represents an enum.
   *
   * @return  {@code true} if the provided type represents an enum, or
   *          {@code false} if not.
   */
  public boolean isEnum()
  {
    return isEnum;
  }



  /**
   * Indicates whether the provided type represents a list.
   *
   * @return  {@code true} if the provided type represents a list, or
   *          {@code false} if not.
   */
  public boolean isList()
  {
    return isList;
  }



  /**
   * Indicates whether the provided type represents a set.
   *
   * @return  {@code true} if the provided type represents a set, or
   *          {@code false} if not.
   */
  public boolean isSet()
  {
    return isSet;
  }



  /**
   * Indicates whether the provided type is one that can hold multiple values.
   * It will be considered able to hold multiple values if and only if the
   * provided type is an array, a list, or a set.
   *
   * @return  {@code true} if the provided type is one that can hold multiple
   *          values, or {@code false} if not.
   */
  public boolean isMultiValued()
  {
    return (isArray || isList || isSet);
  }
}
