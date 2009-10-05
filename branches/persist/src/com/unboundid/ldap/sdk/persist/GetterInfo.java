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
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import com.unboundid.ldap.sdk.Attribute;

import static com.unboundid.ldap.sdk.persist.PersistMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides a data structure that holds information about an
 * annotated getter method.
 */
final class GetterInfo
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

  // Indicates whether the associated method value should be included in the
  // filter created for search operations.
  private final boolean includeInSearchFilter;

  // The class that contains the associated method.
  private final Class<?> containingClass;

  // The method with which this object is associated.
  private final Method method;

  // The encoder used for this method.
  private final LDAPFieldEncoder encoder;

  // The name of the associated attribute type.
  private final String attributeName;

  // The names of the object classes for the associated attribute.
  private final String[] objectClasses;



  /**
   * Creates a new getter info object from the provided method.
   *
   * @param  m  The method to use to create this object.
   * @param  c  The class which holds the method.
   *
   * @throws  LDAPPersistException  If a problem occurs while processing the
   *                                given method.
   */
  GetterInfo(final Method m, final Class<?> c)
       throws LDAPPersistException
  {
    ensureNotNull(m, c);

    method = m;
    m.setAccessible(true);

    final LDAPFieldGetter  a = m.getAnnotation(LDAPFieldGetter.class);
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

    containingClass       = c;
    includeInRDN          = a.inRDN();
    includeInAdd          = (includeInRDN || a.inAdd());
    includeInModify       = a.inModify();
    includeInSearchFilter = a.inFilter();
    attributeName         = a.attribute();

    final int modifiers = m.getModifiers();
    if (Modifier.isStatic(modifiers))
    {
      throw new LDAPPersistException(ERR_GETTER_INFO_METHOD_STATIC.get(
           m.getName(), c.getName()));
    }

    final Class<?>[] params = m.getParameterTypes();
    if (params.length > 0)
    {
      throw new LDAPPersistException(ERR_GETTER_INFO_METHOD_TAKES_ARGUMENTS.get(
           m.getName(), c.getName()));
    }

    try
    {
      encoder = a.encoderClass().newInstance();
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPPersistException(ERR_GETTER_INFO_CANNOT_GET_ENCODER.get(
           a.encoderClass().getName(), m.getName(), c.getName(),
           getExceptionMessage(e)), e);
    }

    if (! encoder.supportsType(m.getReturnType()))
    {
      throw new LDAPPersistException(
           ERR_GETTER_INFO_ENCODER_UNSUPPORTED_TYPE.get(
                encoder.getClass().getName(), m.getName(), c.getName(),
                m.getReturnType().getName()));
    }

    final String structuralClass;
    if (o.structuralClass().length() == 0)
    {
      structuralClass = getUnqualifiedClassName(c);
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
  }



  /**
   * Retrieves the method with which this object is associated.
   *
   * @return  The method with which this object is associated.
   */
  Method getMethod()
  {
    return method;
  }



  /**
   * Retrieves the class that is marked with the {@link LDAPObject} annotation
   * and contains the associated field.
   *
   * @return  The class that contains the associated field.
   */
  Class<?> getContainingClass()
  {
    return containingClass;
  }



  /**
   * Indicates whether the associated method value should be included in entries
   * generated for add operations.
   *
   * @return  {@code true} if the associated method value should be included in
   *          entries generated for add operations, or {@code false} if not.
   */
  boolean includeInAdd()
  {
    return includeInAdd;
  }



  /**
   * Indicates whether the associated method value should be considered for
   * inclusion in the set of modifications generated for modify operations.
   *
   * @return  {@code true} if the associated method value should be considered
   *          for inclusion in the set of modifications generated for modify
   *          operations, or {@code false} if not.
   */
  boolean includeInModify()
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
  boolean includeInRDN()
  {
    return includeInRDN;
  }



  /**
   * Indicates whether the associated method value should be considered for
   * inclusion in filters generated for search operations.
   *
   * @return  {@code true} if the associated method value should be considered
   *          for inclusion in filters generated for search operations, or
   *          {@code false} if not.
   */
  boolean includeInSearchFilter()
  {
    return includeInSearchFilter;
  }



  /**
   * Retrieves the encoder that should be used for the associated method.
   *
   * @return  The encoder that should be used for the associated method.
   */
  LDAPFieldEncoder getEncoder()
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
  String getAttributeName()
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
  String[] getObjectClasses()
  {
    return objectClasses;
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
  Attribute encode(final Object o)
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
    catch (LDAPPersistException lpe)
    {
      debugException(lpe);
      throw lpe;
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPPersistException(ERR_GETTER_INFO_CANNOT_ENCODE.get(
           method.getName(), containingClass.getName(), getExceptionMessage(e)),
           e);
    }
  }
}
