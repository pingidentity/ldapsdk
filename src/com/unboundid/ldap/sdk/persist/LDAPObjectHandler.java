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
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.schema.ObjectClassDefinition;
import com.unboundid.ldap.sdk.schema.ObjectClassType;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.persist.PersistMessages.*;



/**
 * This class provides a mechanism for validating, encoding, and decoding
 * objects marked with the {@link LDAPObject} annotation type.
 *
 * @param  <T>  The type of object handled by this class.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPObjectHandler<T>
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1480360011153517161L;



  // The object class attribute to include in entries that are created.
  @NotNull private final Attribute objectClassAttribute;

  // The type of object handled by this class.
  @NotNull private final Class<T> type;

  // The constructor to use to create a new instance of the class.
  @NotNull private final Constructor<T> constructor;

  // The default parent DN for entries created from objects of the associated
  //  type.
  @NotNull private final DN defaultParentDN;

  // The field that will be used to hold the DN of the entry.
  @Nullable private final Field dnField;

  // The field that will be used to hold the entry contents.
  @Nullable private final Field entryField;

  // The LDAPObject annotation for the associated object.
  @NotNull private final LDAPObject ldapObject;

  // The LDAP object handler for the superclass, if applicable.
  @Nullable private final LDAPObjectHandler<? super T> superclassHandler;

  // The list of fields for with a filter usage of ALWAYS_ALLOWED.
  @NotNull private final List<FieldInfo> alwaysAllowedFilterFields;

  // The list of fields for with a filter usage of CONDITIONALLY_ALLOWED.
  @NotNull private final List<FieldInfo> conditionallyAllowedFilterFields;

  // The list of fields for with a filter usage of REQUIRED.
  @NotNull private final List<FieldInfo> requiredFilterFields;

  // The list of fields for this class that should be used to construct the RDN.
  @NotNull private final List<FieldInfo> rdnFields;

  // The list of getter methods for with a filter usage of ALWAYS_ALLOWED.
  @NotNull private final List<GetterInfo> alwaysAllowedFilterGetters;

  // The list of getter methods for with a filter usage of
  // CONDITIONALLY_ALLOWED.
  @NotNull private final List<GetterInfo> conditionallyAllowedFilterGetters;

  // The list of getter methods for with a filter usage of REQUIRED.
  @NotNull private final List<GetterInfo> requiredFilterGetters;

  // The list of getters for this class that should be used to construct the
  // RDN.
  @NotNull private final List<GetterInfo> rdnGetters;

  // The map of attribute names to their corresponding fields.
  @NotNull private final Map<String,FieldInfo> fieldMap;

  // The map of attribute names to their corresponding getter methods.
  @NotNull private final Map<String,GetterInfo> getterMap;

  // The map of attribute names to their corresponding setter methods.
  @NotNull private final Map<String,SetterInfo> setterMap;

  // The method that should be invoked on an object after all other decode
  // processing has been performed.
  @Nullable private final Method postDecodeMethod;

  // The method that should be invoked on an object after all other encode
  // processing has been performed.
  @Nullable private final Method postEncodeMethod;

  // The structural object class that should be used for entries created from
  // objects of the associated type.
  @NotNull private final String structuralClass;

  // The set of attributes that should be requested when performing a search.
  // It will not include lazily-loaded attributes.
  @NotNull private final String[] attributesToRequest;

  // The auxiliary object classes that should should used for entries created
  // from objects of the associated type.
  @NotNull private final String[] auxiliaryClasses;

  // The set of attributes that will be requested if @LDAPObject has
  // requestAllAttributes is false.  Even if requestAllAttributes is true, this
  // may be used if a subclass has requestAllAttributes set to false.
  @NotNull private final String[] explicitAttributesToRequest;

  // The set of attributes that should be lazily loaded.
  @NotNull private final String[] lazilyLoadedAttributes;

  // The superior object classes that should should used for entries created
  // from objects of the associated type.
  @NotNull private final String[] superiorClasses;



  /**
   * Creates a new instance of this handler that will handle objects of the
   * specified type.
   *
   * @param  type  The type of object that will be handled by this class.
   *
   * @throws  LDAPPersistException  If there is a problem with the provided
   *                                class that makes it unsuitable for use with
   *                                the persistence framework.
   */
  @SuppressWarnings({"unchecked", "rawtypes"})
  LDAPObjectHandler(@NotNull final Class<T> type)
       throws LDAPPersistException
  {
    this.type = type;

    final Class<? super T> superclassType = type.getSuperclass();
    if (superclassType == null)
    {
      superclassHandler = null;
    }
    else
    {
      final LDAPObject superclassAnnotation =
           superclassType.getAnnotation(LDAPObject.class);
      if (superclassAnnotation == null)
      {
        superclassHandler = null;
      }
      else
      {
        superclassHandler = new LDAPObjectHandler(superclassType);
      }
    }

    final TreeMap<String,FieldInfo>  fields  = new TreeMap<>();
    final TreeMap<String,GetterInfo> getters = new TreeMap<>();
    final TreeMap<String,SetterInfo> setters = new TreeMap<>();

    ldapObject = type.getAnnotation(LDAPObject.class);
    if (ldapObject == null)
    {
      throw new LDAPPersistException(
           ERR_OBJECT_HANDLER_OBJECT_NOT_ANNOTATED.get(type.getName()));
    }

    final LinkedHashMap<String,String> objectClasses =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(10));

    final String oc = ldapObject.structuralClass();
    if (oc.isEmpty())
    {
      structuralClass = StaticUtils.getUnqualifiedClassName(type);
    }
    else
    {
      structuralClass = oc;
    }

    final StringBuilder invalidReason = new StringBuilder();
    if (PersistUtils.isValidLDAPName(structuralClass, invalidReason))
    {
      objectClasses.put(StaticUtils.toLowerCase(structuralClass),
           structuralClass);
    }
    else
    {
      throw new LDAPPersistException(
           ERR_OBJECT_HANDLER_INVALID_STRUCTURAL_CLASS.get(type.getName(),
                structuralClass, invalidReason.toString()));
    }

    auxiliaryClasses = ldapObject.auxiliaryClass();
    for (final String auxiliaryClass : auxiliaryClasses)
    {
      if (PersistUtils.isValidLDAPName(auxiliaryClass, invalidReason))
      {
        objectClasses.put(StaticUtils.toLowerCase(auxiliaryClass),
             auxiliaryClass);
      }
      else
      {
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_INVALID_AUXILIARY_CLASS.get(type.getName(),
                  auxiliaryClass, invalidReason.toString()));
      }
    }

    superiorClasses = ldapObject.superiorClass();
    for (final String superiorClass : superiorClasses)
    {
      if (PersistUtils.isValidLDAPName(superiorClass, invalidReason))
      {
        objectClasses.put(StaticUtils.toLowerCase(superiorClass),
             superiorClass);
      }
      else
      {
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_INVALID_SUPERIOR_CLASS.get(type.getName(),
                  superiorClass, invalidReason.toString()));
      }
    }

    if (superclassHandler != null)
    {
      for (final String s : superclassHandler.objectClassAttribute.getValues())
      {
        objectClasses.put(StaticUtils.toLowerCase(s), s);
      }
    }

    objectClassAttribute = new Attribute("objectClass", objectClasses.values());


    final String parentDNStr = ldapObject.defaultParentDN();
    try
    {
      if ((parentDNStr.isEmpty()) && (superclassHandler != null))
      {
        defaultParentDN = superclassHandler.getDefaultParentDN();
      }
      else
      {
        defaultParentDN = new DN(parentDNStr);
      }
    }
    catch (final LDAPException le)
    {
      throw new LDAPPersistException(
           ERR_OBJECT_HANDLER_INVALID_DEFAULT_PARENT.get(type.getName(),
                parentDNStr, le.getMessage()), le);
    }


    final String postDecodeMethodName = ldapObject.postDecodeMethod();
    if (! postDecodeMethodName.isEmpty())
    {
      try
      {
        postDecodeMethod = type.getDeclaredMethod(postDecodeMethodName);
        postDecodeMethod.setAccessible(true);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_INVALID_POST_DECODE_METHOD.get(type.getName(),
                  postDecodeMethodName, StaticUtils.getExceptionMessage(e)),
             e);
      }
    }
    else
    {
      postDecodeMethod = null;
    }


    final String postEncodeMethodName = ldapObject.postEncodeMethod();
    if (! postEncodeMethodName.isEmpty())
    {
      try
      {
        postEncodeMethod = type.getDeclaredMethod(postEncodeMethodName,
             Entry.class);
        postEncodeMethod.setAccessible(true);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_INVALID_POST_ENCODE_METHOD.get(type.getName(),
                  postEncodeMethodName, StaticUtils.getExceptionMessage(e)),
             e);
      }
    }
    else
    {
      postEncodeMethod = null;
    }


    try
    {
      constructor = type.getDeclaredConstructor();
      constructor.setAccessible(true);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPPersistException(
           ERR_OBJECT_HANDLER_NO_DEFAULT_CONSTRUCTOR.get(type.getName()), e);
    }

    Field tmpDNField = null;
    Field tmpEntryField = null;
    final LinkedList<FieldInfo> tmpRFilterFields = new LinkedList<>();
    final LinkedList<FieldInfo> tmpAAFilterFields = new LinkedList<>();
    final LinkedList<FieldInfo> tmpCAFilterFields = new LinkedList<>();
    final LinkedList<FieldInfo> tmpRDNFields = new LinkedList<>();
    for (final Field f : type.getDeclaredFields())
    {
      final LDAPField fieldAnnotation = f.getAnnotation(LDAPField.class);
      final LDAPDNField dnFieldAnnotation = f.getAnnotation(LDAPDNField.class);
      final LDAPEntryField entryFieldAnnotation =
           f.getAnnotation(LDAPEntryField.class);

      if (fieldAnnotation != null)
      {
        f.setAccessible(true);

        final FieldInfo fieldInfo = new FieldInfo(f, type);
        final String attrName =
             StaticUtils.toLowerCase(fieldInfo.getAttributeName());
        if (fields.containsKey(attrName))
        {
          throw new LDAPPersistException(ERR_OBJECT_HANDLER_ATTR_CONFLICT.get(
               type.getName(), fieldInfo.getAttributeName()));
        }
        else
        {
          fields.put(attrName, fieldInfo);
        }

        switch (fieldInfo.getFilterUsage())
        {
          case REQUIRED:
            tmpRFilterFields.add(fieldInfo);
            break;
          case ALWAYS_ALLOWED:
            tmpAAFilterFields.add(fieldInfo);
            break;
          case CONDITIONALLY_ALLOWED:
            tmpCAFilterFields.add(fieldInfo);
            break;
          case EXCLUDED:
          default:
            // No action required.
            break;
        }

        if (fieldInfo.includeInRDN())
        {
          tmpRDNFields.add(fieldInfo);
        }
      }

      if (dnFieldAnnotation != null)
      {
        f.setAccessible(true);

        if (fieldAnnotation != null)
        {
          throw new LDAPPersistException(
               ERR_OBJECT_HANDLER_CONFLICTING_FIELD_ANNOTATIONS.get(
                    type.getName(), "LDAPField", "LDAPDNField", f.getName()));
        }

        if (tmpDNField != null)
        {
          throw new LDAPPersistException(
               ERR_OBJECT_HANDLER_MULTIPLE_DN_FIELDS.get(type.getName()));
        }

        final int modifiers = f.getModifiers();
        if (Modifier.isFinal(modifiers))
        {
          throw new LDAPPersistException(ERR_OBJECT_HANDLER_DN_FIELD_FINAL.get(
               f.getName(), type.getName()));
        }
        else if (Modifier.isStatic(modifiers))
        {
          throw new LDAPPersistException(ERR_OBJECT_HANDLER_DN_FIELD_STATIC.get(
               f.getName(), type.getName()));
        }

        final Class<?> fieldType = f.getType();
        if (fieldType.equals(String.class))
        {
          tmpDNField = f;
        }
        else
        {
          throw new LDAPPersistException(
               ERR_OBJECT_HANDLER_INVALID_DN_FIELD_TYPE.get(type.getName(),
                    f.getName(), fieldType.getName()));
        }
      }

      if (entryFieldAnnotation != null)
      {
        f.setAccessible(true);

        if (fieldAnnotation != null)
        {
          throw new LDAPPersistException(
               ERR_OBJECT_HANDLER_CONFLICTING_FIELD_ANNOTATIONS.get(
                    type.getName(), "LDAPField", "LDAPEntryField",
                    f.getName()));
        }

        if (tmpEntryField != null)
        {
          throw new LDAPPersistException(
               ERR_OBJECT_HANDLER_MULTIPLE_ENTRY_FIELDS.get(type.getName()));
        }

        final int modifiers = f.getModifiers();
        if (Modifier.isFinal(modifiers))
        {
          throw new LDAPPersistException(
               ERR_OBJECT_HANDLER_ENTRY_FIELD_FINAL.get(f.getName(),
                    type.getName()));
        }
        else if (Modifier.isStatic(modifiers))
        {
          throw new LDAPPersistException(
               ERR_OBJECT_HANDLER_ENTRY_FIELD_STATIC.get(f.getName(),
                    type.getName()));
        }

        final Class<?> fieldType = f.getType();
        if (fieldType.equals(ReadOnlyEntry.class))
        {
          tmpEntryField = f;
        }
        else
        {
          throw new LDAPPersistException(
               ERR_OBJECT_HANDLER_INVALID_ENTRY_FIELD_TYPE.get(type.getName(),
                    f.getName(), fieldType.getName()));
        }
      }
    }

    dnField = tmpDNField;
    entryField = tmpEntryField;
    requiredFilterFields = Collections.unmodifiableList(tmpRFilterFields);
    alwaysAllowedFilterFields = Collections.unmodifiableList(tmpAAFilterFields);
    conditionallyAllowedFilterFields =
         Collections.unmodifiableList(tmpCAFilterFields);
    rdnFields    = Collections.unmodifiableList(tmpRDNFields);

    final LinkedList<GetterInfo> tmpRFilterGetters = new LinkedList<>();
    final LinkedList<GetterInfo> tmpAAFilterGetters = new LinkedList<>();
    final LinkedList<GetterInfo> tmpCAFilterGetters = new LinkedList<>();
    final LinkedList<GetterInfo> tmpRDNGetters = new LinkedList<>();
    for (final Method m : type.getDeclaredMethods())
    {
      final LDAPGetter getter = m.getAnnotation(LDAPGetter.class);
      final LDAPSetter setter = m.getAnnotation(LDAPSetter.class);

      if (getter != null)
      {
        m.setAccessible(true);

        if (setter != null)
        {
          throw new LDAPPersistException(
               ERR_OBJECT_HANDLER_CONFLICTING_METHOD_ANNOTATIONS.get(
                    type.getName(), "LDAPGetter", "LDAPSetter",
                    m.getName()));
        }

        final GetterInfo methodInfo = new GetterInfo(m, type);
        final String attrName =
             StaticUtils.toLowerCase(methodInfo.getAttributeName());
        if (fields.containsKey(attrName) || getters.containsKey(attrName))
        {
          throw new LDAPPersistException(ERR_OBJECT_HANDLER_ATTR_CONFLICT.get(
               type.getName(), methodInfo.getAttributeName()));
        }
        else
        {
          getters.put(attrName, methodInfo);
        }

        switch (methodInfo.getFilterUsage())
        {
          case REQUIRED:
            tmpRFilterGetters.add(methodInfo);
            break;
          case ALWAYS_ALLOWED:
            tmpAAFilterGetters.add(methodInfo);
            break;
          case CONDITIONALLY_ALLOWED:
            tmpCAFilterGetters.add(methodInfo);
            break;
          case EXCLUDED:
          default:
            // No action required.
            break;
        }

        if (methodInfo.includeInRDN())
        {
          tmpRDNGetters.add(methodInfo);
        }
      }

      if (setter != null)
      {
        m.setAccessible(true);

        final SetterInfo methodInfo = new SetterInfo(m, type);
        final String attrName =
             StaticUtils.toLowerCase(methodInfo.getAttributeName());
        if (fields.containsKey(attrName) || setters.containsKey(attrName))
        {
          throw new LDAPPersistException(ERR_OBJECT_HANDLER_ATTR_CONFLICT.get(
               type.getName(), methodInfo.getAttributeName()));
        }
        else
        {
          setters.put(attrName, methodInfo);
        }
      }
    }

    requiredFilterGetters = Collections.unmodifiableList(tmpRFilterGetters);
    alwaysAllowedFilterGetters =
         Collections.unmodifiableList(tmpAAFilterGetters);
    conditionallyAllowedFilterGetters =
         Collections.unmodifiableList(tmpCAFilterGetters);

    rdnGetters = Collections.unmodifiableList(tmpRDNGetters);
    if (rdnFields.isEmpty() && rdnGetters.isEmpty() &&
        (superclassHandler == null))
    {
      throw new LDAPPersistException(ERR_OBJECT_HANDLER_NO_RDN_DEFINED.get(
           type.getName()));
    }

    fieldMap  = Collections.unmodifiableMap(fields);
    getterMap = Collections.unmodifiableMap(getters);
    setterMap = Collections.unmodifiableMap(setters);


    final TreeSet<String> attrSet = new TreeSet<>();
    final TreeSet<String> lazySet = new TreeSet<>();
    for (final FieldInfo i : fields.values())
    {
      if (i.lazilyLoad())
      {
        lazySet.add(i.getAttributeName());
      }
      else
      {
        attrSet.add(i.getAttributeName());
      }
    }

    for (final SetterInfo i : setters.values())
    {
      attrSet.add(i.getAttributeName());
    }

    if (superclassHandler != null)
    {
      attrSet.addAll(Arrays.asList(
           superclassHandler.explicitAttributesToRequest));
      lazySet.addAll(Arrays.asList(superclassHandler.lazilyLoadedAttributes));
    }

    explicitAttributesToRequest = new String[attrSet.size()];
    attrSet.toArray(explicitAttributesToRequest);

    if (requestAllAttributes())
    {
      attributesToRequest = new String[] { "*", "+" };
    }
    else
    {
      attributesToRequest = explicitAttributesToRequest;
    }

    lazilyLoadedAttributes = new String[lazySet.size()];
    lazySet.toArray(lazilyLoadedAttributes);
  }



  /**
   * Retrieves the type of object handled by this class.
   *
   * @return  The type of object handled by this class.
   */
  @NotNull()
  public Class<T> getType()
  {
    return type;
  }



  /**
   * Retrieves the {@code LDAPObjectHandler} object for the superclass of the
   * associated type, if it is marked with the {@code LDAPObject annotation}.
   *
   * @return  The {@code LDAPObjectHandler} object for the superclass of the
   *          associated type, or {@code null} if the superclass is not marked
   *          with the {@code LDAPObject} annotation.
   */
  @Nullable()
  public LDAPObjectHandler<?> getSuperclassHandler()
  {
    return superclassHandler;
  }



  /**
   * Retrieves the {@link LDAPObject} annotation for the associated class.
   *
   * @return  The {@code LDAPObject} annotation for the associated class.
   */
  @NotNull()
  public LDAPObject getLDAPObjectAnnotation()
  {
    return ldapObject;
  }



  /**
   * Retrieves the constructor used to create a new instance of the appropriate
   * type.
   *
   * @return  The constructor used to create a new instance of the appropriate
   *          type.
   */
  @NotNull()
  public Constructor<T> getConstructor()
  {
    return constructor;
  }



  /**
   * Retrieves the field that will be used to hold the DN of the associated
   * entry, if defined.
   *
   * @return  The field that will be used to hold the DN of the associated
   *          entry, or {@code null} if no DN field is defined in the associated
   *          object type.
   */
  @Nullable()
  public Field getDNField()
  {
    return dnField;
  }



  /**
   * Retrieves the field that will be used to hold a read-only copy of the entry
   * used to create the object instance, if defined.
   *
   * @return  The field that will be used to hold a read-only copy of the entry
   *          used to create the object instance, or {@code null} if no entry
   *          field is defined in the associated object type.
   */
  @Nullable()
  public Field getEntryField()
  {
    return entryField;
  }



  /**
   * Retrieves the default parent DN for objects of the associated type.
   *
   * @return  The default parent DN for objects of the associated type.
   */
  @NotNull()
  public DN getDefaultParentDN()
  {
    return defaultParentDN;
  }



  /**
   * Retrieves the name of the structural object class for objects of the
   * associated type.
   *
   * @return  The name of the structural object class for objects of the
   *          associated type.
   */
  @NotNull()
  public String getStructuralClass()
  {
    return structuralClass;
  }



  /**
   * Retrieves the names of the auxiliary object classes for objects of the
   * associated type.
   *
   * @return  The names of the auxiliary object classes for objects of the
   *          associated type.  It may be empty if no auxiliary classes are
   *          defined.
   */
  @NotNull()
  public String[] getAuxiliaryClasses()
  {
    return auxiliaryClasses;
  }



  /**
   * Retrieves the names of the superior object classes for objects of the
   * associated type.
   *
   * @return  The names of the superior object classes for objects of the
   *          associated type.  It may be empty if no superior classes are
   *          defined.
   */
  @NotNull()
  public String[] getSuperiorClasses()
  {
    return superiorClasses;
  }



  /**
   * Indicates whether to request all attributes.  This will return {@code true}
   * if the associated {@code LDAPObject}, or any {@code LDAPObject} for any
   * superclass, has {@code requestAllAttributes} set to {@code true}.
   *
   * @return  {@code true} if {@code LDAPObject} has
   *          {@code requestAllAttributes} set to {@code true} for any class in
   *          the hierarchy, or {@code false} if not.
   */
  public boolean requestAllAttributes()
  {
    return (ldapObject.requestAllAttributes() ||
            ((superclassHandler != null) &&
             superclassHandler.requestAllAttributes()));
  }



  /**
   * Retrieves the names of the attributes that should be requested when
   * performing a search.  It will not include lazily-loaded attributes.
   *
   * @return  The names of the attributes that should be requested when
   *          performing a search.
   */
  @NotNull()
  public String[] getAttributesToRequest()
  {
    return attributesToRequest;
  }



  /**
   * Retrieves the names of the attributes that should be lazily loaded for
   * objects of this type.
   *
   * @return  The names of the attributes that should be lazily loaded for
   *          objects of this type.  It may be empty if no attributes should be
   *          lazily-loaded.
   */
  @NotNull()
  public String[] getLazilyLoadedAttributes()
  {
    return lazilyLoadedAttributes;
  }



  /**
   * Retrieves the DN of the entry in which the provided object is stored, if
   * available.  The entry DN will not be available if the provided object was
   * not retrieved using the persistence framework, or if the associated class
   * (or one of its superclasses) does not have a field marked with either the
   * {@link LDAPDNField} or {@link LDAPEntryField} annotation.
   *
   * @param  o  The object for which to retrieve the associated entry DN.
   *
   * @return  The DN of the entry in which the provided object is stored, or
   *          {@code null} if that is not available.
   *
   * @throws  LDAPPersistException  If a problem occurred while attempting to
   *                                obtain the entry DN.
   */
  @Nullable()
  public String getEntryDN(@NotNull final T o)
         throws LDAPPersistException
  {
    final String dnFieldValue = getDNFieldValue(o);
    if (dnFieldValue != null)
    {
      return dnFieldValue;
    }

    final ReadOnlyEntry entry = getEntry(o);
    if (entry != null)
    {
      return entry.getDN();
    }

    return null;
  }



  /**
   * Retrieves the value of the DN field for the provided object.  If there is
   * no DN field in this object handler but there is one defined for a handler
   * for one of its superclasses, then it will be obtained recursively.
   *
   * @param  o  The object for which to retrieve the associated entry DN.
   *
   * @return  The value of the DN field for the provided object.
   *
   * @throws  LDAPPersistException  If a problem is encountered while attempting
   *                                to access the value of the DN field.
   */
  @Nullable()
  private String getDNFieldValue(@NotNull final T o)
          throws LDAPPersistException
  {
    if (dnField != null)
    {
      try
      {
        final Object dnObject = dnField.get(o);
        if (dnObject == null)
        {
          return null;
        }
        else
        {
          return String.valueOf(dnObject);
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_ERROR_ACCESSING_DN_FIELD.get(dnField.getName(),
                  type.getName(), StaticUtils.getExceptionMessage(e)),
             e);
      }
    }

    if (superclassHandler != null)
    {
      return superclassHandler.getDNFieldValue(o);
    }

    return null;
  }



  /**
   * Retrieves a read-only copy of the entry that was used to initialize the
   * provided object, if available.  The entry will only be available if the
   * object was retrieved from the directory using the persistence framework and
   * the associated class (or one of its superclasses) has a field marked with
   * the {@link LDAPEntryField} annotation.
   *
   * @param  o  The object for which to retrieve the read-only entry.
   *
   * @return  A read-only copy of the entry that was used to initialize the
   *          provided object, or {@code null} if that is not available.
   *
   * @throws  LDAPPersistException  If a problem occurred while attempting to
   *                                obtain the entry DN.
   */
  @Nullable()
  public ReadOnlyEntry getEntry(@NotNull final T o)
         throws LDAPPersistException
  {
    if (entryField != null)
    {
      try
      {
        final Object entryObject = entryField.get(o);
        if (entryObject == null)
        {
          return null;
        }
        else
        {
          return (ReadOnlyEntry) entryObject;
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_ERROR_ACCESSING_ENTRY_FIELD.get(
                  entryField.getName(), type.getName(),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }

    if (superclassHandler != null)
    {
      return superclassHandler.getEntry(o);
    }

    return null;
  }



  /**
   * Retrieves a map of all fields in the class that should be persisted as LDAP
   * attributes.  The keys in the map will be the lowercase names of the LDAP
   * attributes used to persist the information, and the values will be
   * information about the fields associated with those attributes.
   *
   * @return  A map of all fields in the class that should be persisted as LDAP
   *          attributes.
   */
  @NotNull()
  public Map<String,FieldInfo> getFields()
  {
    return fieldMap;
  }



  /**
   * Retrieves a map of all getter methods in the class whose values should be
   * persisted as LDAP attributes.  The keys in the map will be the lowercase
   * names of the LDAP attributes used to persist the information, and the
   * values will be information about the getter methods associated with those
   * attributes.
   *
   * @return  A map of all getter methods in the class whose values should be
   *          persisted as LDAP attributes.
   */
  @NotNull()
  public Map<String,GetterInfo> getGetters()
  {
    return getterMap;
  }



  /**
   * Retrieves a map of all setter methods in the class that should be invoked
   * with information read from LDAP attributes.  The keys in the map will be
   * the lowercase names of the LDAP attributes with the information used to
   * invoke the setter, and the values will be information about the setter
   * methods associated with those attributes.
   *
   * @return  A map of all setter methods in the class that should be invoked
   *          with information read from LDAP attributes.
   */
  @NotNull()
  public Map<String,SetterInfo> getSetters()
  {
    return setterMap;
  }



  /**
   * Constructs a list of LDAP object class definitions which may be added to
   * the directory server schema to allow it to hold objects of this type.  Note
   * that the object identifiers used for the constructed object class
   * definitions are not required to be valid or unique.
   *
   * @param  a  The OID allocator to use to generate the object identifiers for
   *            the constructed attribute types.  It must not be {@code null}.
   *
   * @return  A list of object class definitions that may be used to represent
   *          objects of the associated type in an LDAP directory.
   *
   * @throws  LDAPPersistException  If a problem occurs while attempting to
   *                                generate the list of object class
   *                                definitions.
   */
  @NotNull()
  List<ObjectClassDefinition> constructObjectClasses(
                                   @NotNull final OIDAllocator a)
         throws LDAPPersistException
  {
    final LinkedHashMap<String,ObjectClassDefinition> ocMap =
         new LinkedHashMap<>(
              StaticUtils.computeMapCapacity(1 + auxiliaryClasses.length));

    if (superclassHandler != null)
    {
      for (final ObjectClassDefinition d :
           superclassHandler.constructObjectClasses(a))
      {
        ocMap.put(StaticUtils.toLowerCase(d.getNameOrOID()), d);
      }
    }

    final String lowerStructuralClass =
         StaticUtils.toLowerCase(structuralClass);
    if (! ocMap.containsKey(lowerStructuralClass))
    {
      if (superclassHandler == null)
      {
        ocMap.put(lowerStructuralClass, constructObjectClass(structuralClass,
             "top", ObjectClassType.STRUCTURAL, a));
      }
      else
      {
        ocMap.put(lowerStructuralClass, constructObjectClass(structuralClass,
             superclassHandler.getStructuralClass(), ObjectClassType.STRUCTURAL,
             a));
      }
    }

    for (final String s : auxiliaryClasses)
    {
      final String lowerName = StaticUtils.toLowerCase(s);
      if (! ocMap.containsKey(lowerName))
      {
        ocMap.put(lowerName,
             constructObjectClass(s, "top", ObjectClassType.AUXILIARY, a));
      }
    }

    return Collections.unmodifiableList(new ArrayList<>(ocMap.values()));
  }



  /**
   * Constructs an LDAP object class definition for the object class with the
   * specified name.
   *
   * @param  name  The name of the object class to create.  It must not be
   *               {@code null}.
   * @param  sup   The name of the superior object class.  It must not be
   *               {@code null}.
   * @param  type  The type of object class to create.  It must not be
   *               {@code null}.
   * @param  a     The OID allocator to use to generate the object identifiers
   *               for the constructed attribute types.  It must not be
   *               {@code null}.
   *
   * @return  The constructed object class definition.
   */
  @NotNull()
  private ObjectClassDefinition constructObjectClass(@NotNull final String name,
                                     @NotNull final String sup,
                                     @NotNull final ObjectClassType type,
                                     @NotNull final OIDAllocator a)
  {
    final TreeMap<String,String> requiredAttrs = new TreeMap<>();
    final TreeMap<String,String> optionalAttrs = new TreeMap<>();


    // Extract the attributes for all of the fields.
    for (final FieldInfo i : fieldMap.values())
    {
      boolean found = false;
      for (final String s : i.getObjectClasses())
      {
        if (name.equalsIgnoreCase(s))
        {
          found = true;
          break;
        }
      }

      if (! found)
      {
        continue;
      }

      final String attrName  = i.getAttributeName();
      final String lowerName = StaticUtils.toLowerCase(attrName);
      if (i.includeInRDN() ||
          (i.isRequiredForDecode() && i.isRequiredForEncode()))
      {
        requiredAttrs.put(lowerName, attrName);
      }
      else
      {
        optionalAttrs.put(lowerName, attrName);
      }
    }


    // Extract the attributes for all of the getter methods.
    for (final GetterInfo i : getterMap.values())
    {
      boolean found = false;
      for (final String s : i.getObjectClasses())
      {
        if (name.equalsIgnoreCase(s))
        {
          found = true;
          break;
        }
      }

      if (! found)
      {
        continue;
      }

      final String attrName  = i.getAttributeName();
      final String lowerName = StaticUtils.toLowerCase(attrName);
      if (i.includeInRDN())
      {
        requiredAttrs.put(lowerName, attrName);
      }
      else
      {
        optionalAttrs.put(lowerName, attrName);
      }
    }


    // Extract the attributes for all of the setter methods.  We'll assume that
    // they are all part of the structural object class and all optional.
    if (name.equalsIgnoreCase(structuralClass))
    {
      for (final SetterInfo i : setterMap.values())
      {
        final String attrName  = i.getAttributeName();
        final String lowerName = StaticUtils.toLowerCase(attrName);
        if (requiredAttrs.containsKey(lowerName) ||
             optionalAttrs.containsKey(lowerName))
        {
          continue;
        }

        optionalAttrs.put(lowerName, attrName);
      }
    }

    final String[] reqArray = new String[requiredAttrs.size()];
    requiredAttrs.values().toArray(reqArray);

    final String[] optArray = new String[optionalAttrs.size()];
    optionalAttrs.values().toArray(optArray);

    return new ObjectClassDefinition(a.allocateObjectClassOID(name),
         new String[] { name }, null, false, new String[] { sup }, type,
         reqArray, optArray, null);
  }



  /**
   * Creates a new object based on the contents of the provided entry.
   *
   * @param  e  The entry to use to create and initialize the object.
   *
   * @return  The object created from the provided entry.
   *
   * @throws  LDAPPersistException  If an error occurs while creating or
   *                                initializing the object from the information
   *                                in the provided entry.
   */
  @NotNull()
  T decode(@NotNull final Entry e)
    throws LDAPPersistException
  {
    final T o;
    try
    {
      o = constructor.newInstance();
    }
    catch (final Exception ex)
    {
      Debug.debugException(ex);

      if (ex instanceof InvocationTargetException)
      {
        final Throwable targetException =
             ((InvocationTargetException) ex).getTargetException();
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_ERROR_INVOKING_CONSTRUCTOR.get(type.getName(),
                  StaticUtils.getExceptionMessage(targetException)),
             targetException);
      }
      else
      {
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_ERROR_INVOKING_CONSTRUCTOR.get(type.getName(),
                  StaticUtils.getExceptionMessage(ex)),
             ex);
      }
    }

    decode(o, e);
    return o;
  }



  /**
   * Initializes the provided object from the contents of the provided entry.
   *
   * @param  o  The object to be initialized with the contents of the provided
   *            entry.
   * @param  e  The entry to use to initialize the object.
   *
   * @throws  LDAPPersistException  If an error occurs while initializing the
   *                                object from the information in the provided
   *                                entry.
   */
  void decode(@NotNull final T o, @NotNull final Entry e)
       throws LDAPPersistException
  {
    if (superclassHandler != null)
    {
      superclassHandler.decode(o, e);
    }

    setDNAndEntryFields(o, e);

    final ArrayList<String> failureReasons = new ArrayList<>(5);
    boolean successful = true;

    for (final FieldInfo i : fieldMap.values())
    {
      successful &= i.decode(o, e, failureReasons);
    }

    for (final SetterInfo i : setterMap.values())
    {
      successful &= i.invokeSetter(o, e, failureReasons);
    }

    Throwable cause = null;
    if (postDecodeMethod != null)
    {
      try
      {
        postDecodeMethod.invoke(o);
      }
      catch (final Exception ex)
      {
        Debug.debugException(ex);
        StaticUtils.rethrowIfError(ex);

        if (ex instanceof InvocationTargetException)
        {
          cause = ((InvocationTargetException) ex).getTargetException();
        }
        else
        {
          cause = ex;
        }

        successful = false;
        failureReasons.add(
             ERR_OBJECT_HANDLER_ERROR_INVOKING_POST_DECODE_METHOD.get(
                  postDecodeMethod.getName(), type.getName(),
                  StaticUtils.getExceptionMessage(ex)));
      }
    }

    if (! successful)
    {
      throw new LDAPPersistException(
           StaticUtils.concatenateStrings(failureReasons), o, cause);
    }
  }



  /**
   * Encodes the provided object to an entry suitable for use in an add
   * operation.
   *
   * @param  o         The object to be encoded.
   * @param  parentDN  The parent DN to use by default for the entry that is
   *                   generated.  If the provided object was previously read
   *                   from a directory server and includes a DN field or an
   *                   entry field with the original DN used for the object,
   *                   then that original DN will be used even if it is not
   *                   an immediate subordinate of the provided parent.  This
   *                   may be {@code null} if the entry to create should not
   *                   have a parent but instead should have a DN consisting of
   *                   only a single RDN component.
   *
   * @return  The entry containing an encoded representation of the provided
   *          object.
   *
   * @throws  LDAPPersistException  If a problem occurs while encoding the
   *                                provided object.
   */
  @NotNull()
  Entry encode(@NotNull final T o, @Nullable final String parentDN)
        throws LDAPPersistException
  {
    // Get the attributes that should be included in the entry.
    final LinkedHashMap<String,Attribute> attrMap =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(20));
    attrMap.put("objectClass", objectClassAttribute);

    for (final Map.Entry<String,FieldInfo> e : fieldMap.entrySet())
    {
      final FieldInfo i = e.getValue();
      if (! i.includeInAdd())
      {
        continue;
      }

      final Attribute a = i.encode(o, false);
      if (a != null)
      {
        attrMap.put(e.getKey(), a);
      }
    }

    for (final Map.Entry<String,GetterInfo> e : getterMap.entrySet())
    {
      final GetterInfo i = e.getValue();
      if (! i.includeInAdd())
      {
        continue;
      }

      final Attribute a = i.encode(o);
      if (a != null)
      {
        attrMap.put(e.getKey(), a);
      }
    }


    // Get the DN to use for the entry.
    final String dn = constructDN(o, parentDN, attrMap);
    final Entry entry = new Entry(dn, attrMap.values());

    if (postEncodeMethod != null)
    {
      try
      {
        postEncodeMethod.invoke(o, entry);
      }
      catch (final Exception ex)
      {
        Debug.debugException(ex);

        if (ex instanceof InvocationTargetException)
        {
          final Throwable targetException =
               ((InvocationTargetException) ex).getTargetException();
          throw new LDAPPersistException(
               ERR_OBJECT_HANDLER_ERROR_INVOKING_POST_ENCODE_METHOD.get(
                    postEncodeMethod.getName(), type.getName(),
                    StaticUtils.getExceptionMessage(targetException)),
               targetException);
        }
        else
        {
          throw new LDAPPersistException(
               ERR_OBJECT_HANDLER_ERROR_INVOKING_POST_ENCODE_METHOD.get(
                    postEncodeMethod.getName(), type.getName(),
                    StaticUtils.getExceptionMessage(ex)), ex);
        }
      }
    }

    setDNAndEntryFields(o, entry);

    if (superclassHandler != null)
    {
      final Entry e = superclassHandler.encode(o, parentDN);
      for (final Attribute a : e.getAttributes())
      {
        entry.addAttribute(a);
      }
    }

    return entry;
  }



  /**
   * Sets the DN and entry fields for the provided object, if appropriate.
   *
   * @param  o  The object to be updated.
   * @param  e  The entry with which the object is associated.
   *
   * @throws  LDAPPersistException  If a problem occurs while setting the value
   *                                of the DN or entry field.
   */
  private void setDNAndEntryFields(@NotNull final T o, @NotNull final Entry e)
          throws LDAPPersistException
  {
    if (dnField != null)
    {
      try
      {
        if (dnField.get(o) == null)
        {
          dnField.set(o, e.getDN());
        }
      }
      catch (final Exception ex)
      {
        Debug.debugException(ex);
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_ERROR_SETTING_DN.get(type.getName(), e.getDN(),
                  dnField.getName(), StaticUtils.getExceptionMessage(ex)),
             ex);
      }
    }

    if (entryField != null)
    {
      try
      {
        if (entryField.get(o) == null)
        {
          entryField.set(o, new ReadOnlyEntry(e));
        }
      }
      catch (final Exception ex)
      {
        Debug.debugException(ex);
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_ERROR_SETTING_ENTRY.get(type.getName(),
                  entryField.getName(), StaticUtils.getExceptionMessage(ex)),
             ex);
      }
    }

    if (superclassHandler != null)
    {
      superclassHandler.setDNAndEntryFields(o, e);
    }
  }



  /**
   * Determines the DN that should be used for the entry associated with the
   * given object.  If the provided object was retrieved from the directory
   * using the persistence framework and has a field with either the
   * {@link LDAPDNField} or {@link LDAPEntryField} annotation, then the actual
   * DN of the corresponding entry will be returned.  Otherwise, it will be
   * constructed using the fields and getter methods marked for inclusion in
   * the entry RDN.
   *
   * @param  o         The object for which to determine the appropriate DN.
   * @param  parentDN  The parent DN to use for the constructed DN.  If a
   *                   non-{@code null} value is provided, then that value will
   *                   be used as the parent DN (and the empty string will
   *                   indicate that the generated DN should not have a parent).
   *                   If the value is {@code null}, then the default parent DN
   *                   as defined in the {@link LDAPObject} annotation will be
   *                   used.  If the provided parent DN is {@code null} and the
   *                   {@code LDAPObject} annotation does not specify a default
   *                   parent DN, then the generated DN will not have a parent.
   *
   * @return  The entry DN for the provided object.
   *
   * @throws  LDAPPersistException  If a problem occurs while obtaining the
   *                                entry DN, or if the provided parent DN
   *                                represents an invalid DN.
   */
  @NotNull()
  public String constructDN(@NotNull final T o, @Nullable final String parentDN)
         throws LDAPPersistException
  {
    final String existingDN = getEntryDN(o);
    if (existingDN != null)
    {
      return existingDN;
    }

    final int numRDNs = rdnFields.size() + rdnGetters.size();
    if (numRDNs == 0)
    {
      return superclassHandler.constructDN(o, parentDN);
    }

    final LinkedHashMap<String,Attribute> attrMap =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(numRDNs));

    for (final FieldInfo i : rdnFields)
    {
      final Attribute a = i.encode(o, true);
      if (a == null)
      {
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_RDN_FIELD_MISSING_VALUE.get(type.getName(),
                  i.getField().getName()));
      }

      attrMap.put(StaticUtils.toLowerCase(i.getAttributeName()), a);
    }

    for (final GetterInfo i : rdnGetters)
    {
      final Attribute a = i.encode(o);
      if (a == null)
      {
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_RDN_GETTER_MISSING_VALUE.get(type.getName(),
                  i.getMethod().getName()));
      }

      attrMap.put(StaticUtils.toLowerCase(i.getAttributeName()), a);
    }

    return constructDN(o, parentDN, attrMap);
  }



  /**
   * Determines the DN that should be used for the entry associated with the
   * given object.  If the provided object was retrieved from the directory
   * using the persistence framework and has a field with either the
   * {@link LDAPDNField} or {@link LDAPEntryField} annotation, then the actual
   * DN of the corresponding entry will be returned.  Otherwise, it will be
   * constructed using the fields and getter methods marked for inclusion in
   * the entry RDN.
   *
   * @param  o         The object for which to determine the appropriate DN.
   * @param  parentDN  The parent DN to use for the constructed DN.  If a
   *                   non-{@code null} value is provided, then that value will
   *                   be used as the parent DN (and the empty string will
   *                   indicate that the generated DN should not have a parent).
   *                   If the value is {@code null}, then the default parent DN
   *                   as defined in the {@link LDAPObject} annotation will be
   *                   used.  If the provided parent DN is {@code null} and the
   *                   {@code LDAPObject} annotation does not specify a default
   *                   parent DN, then the generated DN will not have a parent.
   * @param  attrMap   A map of the attributes that will be included in the
   *                   entry and may be used to construct the RDN elements.
   *
   * @return  The entry DN for the provided object.
   *
   * @throws  LDAPPersistException  If a problem occurs while obtaining the
   *                                entry DN, or if the provided parent DN
   *                                represents an invalid DN.
   */
  @NotNull()
  String constructDN(@NotNull final T o, @Nullable final String parentDN,
                     @NotNull final Map<String,Attribute> attrMap)
         throws LDAPPersistException
  {
    final String existingDN = getEntryDN(o);
    if (existingDN != null)
    {
      return existingDN;
    }

    final int numRDNs = rdnFields.size() + rdnGetters.size();
    if (numRDNs == 0)
    {
      return superclassHandler.constructDN(o, parentDN);
    }

    final ArrayList<String> rdnNameList  = new ArrayList<>(numRDNs);
    final ArrayList<byte[]> rdnValueList = new ArrayList<>(numRDNs);
    for (final FieldInfo i : rdnFields)
    {
      final Attribute a =
           attrMap.get(StaticUtils.toLowerCase(i.getAttributeName()));
      if (a == null)
      {
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_RDN_FIELD_MISSING_VALUE.get(type.getName(),
                  i.getField().getName()));
      }

      rdnNameList.add(a.getName());
      rdnValueList.add(a.getValueByteArray());
    }

    for (final GetterInfo i : rdnGetters)
    {
      final Attribute a =
           attrMap.get(StaticUtils.toLowerCase(i.getAttributeName()));
      if (a == null)
      {
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_RDN_GETTER_MISSING_VALUE.get(type.getName(),
                  i.getMethod().getName()));
      }

      rdnNameList.add(a.getName());
      rdnValueList.add(a.getValueByteArray());
    }

    final String[] rdnNames = new String[rdnNameList.size()];
    rdnNameList.toArray(rdnNames);

    final byte[][] rdnValues = new byte[rdnNames.length][];
    rdnValueList.toArray(rdnValues);

    final RDN rdn = new RDN(rdnNames, rdnValues);

    if (parentDN == null)
    {
      return new DN(rdn, defaultParentDN).toString();
    }
    else
    {
      try
      {
        final DN parsedParentDN = new DN(parentDN);
        return new DN(rdn, parsedParentDN).toString();
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        throw new LDAPPersistException(ERR_OBJECT_HANDLER_INVALID_PARENT_DN.get(
             type.getName(), parentDN, le.getMessage()), le);
      }
    }
  }



  /**
   * Creates a list of modifications that can be used to update the stored
   * representation of the provided object in the directory.  If the provided
   * object was retrieved from the directory using the persistence framework and
   * includes a field with the {@link LDAPEntryField} annotation, then that
   * entry will be used to make the returned set of modifications as efficient
   * as possible.  Otherwise, the resulting modifications will include attempts
   * to replace every attribute which are associated with fields or getters
   * that should be used in modify operations.
   *
   * @param  o                 The object to be encoded.
   * @param  deleteNullValues  Indicates whether to include modifications that
   *                           may completely remove an attribute from the
   *                           entry if the corresponding field or getter method
   *                           has a value of {@code null}.
   * @param  byteForByte       Indicates whether to use a byte-for-byte
   *                           comparison to identify which attribute values
   *                           have changed.  Using byte-for-byte comparison
   *                           requires additional processing over using each
   *                           attribute's associated matching rule, but it can
   *                           detect changes that would otherwise be considered
   *                           logically equivalent (e.g., changing the
   *                           capitalization of a value that uses a
   *                           case-insensitive matching rule).
   * @param  attributes        The set of LDAP attributes for which to include
   *                           modifications.  If this is empty or {@code null},
   *                           then all attributes marked for inclusion in the
   *                           modification will be examined.
   *
   * @return  A list of modifications that can be used to update the stored
   *          representation of the provided object in the directory.  It may
   *          be empty if there are no differences identified in the attributes
   *          to be evaluated.
   *
   * @throws  LDAPPersistException  If a problem occurs while computing the set
   *                                of modifications.
   */
  @NotNull()
  List<Modification> getModifications(@NotNull final T o,
                                      final boolean deleteNullValues,
                                      final boolean byteForByte,
                                      @Nullable final String... attributes)
         throws LDAPPersistException
  {
    final ReadOnlyEntry originalEntry;
    if (entryField != null)
    {
      originalEntry = getEntry(o);
    }
    else
    {
      originalEntry = null;
    }

    // If we have an original copy of the entry, then we can try encoding the
    // updated object to a new entry and diff the two entries.
    if (originalEntry != null)
    {
      try
      {
        final T decodedOrig = decode(originalEntry);
        final Entry reEncodedOriginal =
             encode(decodedOrig, originalEntry.getParentDNString());

        final Entry newEntry = encode(o, originalEntry.getParentDNString());
        final List<Modification> mods = Entry.diff(reEncodedOriginal, newEntry,
             true, false, byteForByte, attributes);
        if (! deleteNullValues)
        {
          final Iterator<Modification> iterator = mods.iterator();
          while (iterator.hasNext())
          {
            final Modification m = iterator.next();
            if (m.getRawValues().length == 0)
            {
              iterator.remove();
            }
          }
        }

        // If there are any attributes that should be excluded from
        // modifications, then strip them out.
        HashSet<String> stripAttrs = null;
        for (final FieldInfo i : fieldMap.values())
        {
          if (! i.includeInModify())
          {
            if (stripAttrs == null)
            {
              stripAttrs = new HashSet<>(StaticUtils.computeMapCapacity(10));
            }
            stripAttrs.add(StaticUtils.toLowerCase(i.getAttributeName()));
          }
        }

        for (final GetterInfo i : getterMap.values())
        {
          if (! i.includeInModify())
          {
            if (stripAttrs == null)
            {
              stripAttrs = new HashSet<>(StaticUtils.computeMapCapacity(10));
            }
            stripAttrs.add(StaticUtils.toLowerCase(i.getAttributeName()));
          }
        }

        if (stripAttrs != null)
        {
          final Iterator<Modification> iterator = mods.iterator();
          while (iterator.hasNext())
          {
            final Modification m = iterator.next();
            if (stripAttrs.contains(
                 StaticUtils.toLowerCase(m.getAttributeName())))
            {
              iterator.remove();
            }
          }
        }

        return mods;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
      finally
      {
        setDNAndEntryFields(o, originalEntry);
      }
    }

    final HashSet<String> attrSet;
    if ((attributes == null) || (attributes.length == 0))
    {
      attrSet = null;
    }
    else
    {
      attrSet =
           new HashSet<>(StaticUtils.computeMapCapacity(attributes.length));
      for (final String s : attributes)
      {
        attrSet.add(StaticUtils.toLowerCase(s));
      }
    }

    final ArrayList<Modification> mods = new ArrayList<>(5);

    for (final Map.Entry<String,FieldInfo> e : fieldMap.entrySet())
    {
      final String attrName = StaticUtils.toLowerCase(e.getKey());
      if ((attrSet != null) && (! attrSet.contains(attrName)))
      {
        continue;
      }

      final FieldInfo i = e.getValue();
      if (! i.includeInModify())
      {
        continue;
      }

      final Attribute a = i.encode(o, false);
      if (a == null)
      {
        if (! deleteNullValues)
        {
          continue;
        }

        if ((originalEntry != null) && (! originalEntry.hasAttribute(attrName)))
        {
          continue;
        }

        mods.add(new Modification(ModificationType.REPLACE,
             i.getAttributeName()));
        continue;
      }

      if (originalEntry != null)
      {
        final Attribute originalAttr = originalEntry.getAttribute(attrName);
        if ((originalAttr != null) && originalAttr.equals(a))
        {
        continue;
        }
      }

      mods.add(new Modification(ModificationType.REPLACE, i.getAttributeName(),
           a.getRawValues()));
    }

    for (final Map.Entry<String,GetterInfo> e : getterMap.entrySet())
    {
      final String attrName = StaticUtils.toLowerCase(e.getKey());
      if ((attrSet != null) && (! attrSet.contains(attrName)))
      {
        continue;
      }

      final GetterInfo i = e.getValue();
      if (! i.includeInModify())
      {
        continue;
      }

      final Attribute a = i.encode(o);
      if (a == null)
      {
        if (! deleteNullValues)
        {
          continue;
        }

        if ((originalEntry != null) && (! originalEntry.hasAttribute(attrName)))
        {
          continue;
        }

        mods.add(new Modification(ModificationType.REPLACE,
             i.getAttributeName()));
        continue;
      }

      if (originalEntry != null)
      {
        final Attribute originalAttr = originalEntry.getAttribute(attrName);
        if ((originalAttr != null) && originalAttr.equals(a))
        {
        continue;
        }
      }

      mods.add(new Modification(ModificationType.REPLACE, i.getAttributeName(),
           a.getRawValues()));
    }

    if (superclassHandler != null)
    {
      final List<Modification> superMods =
           superclassHandler.getModifications(o, deleteNullValues, byteForByte,
                attributes);
      final ArrayList<Modification> modsToAdd =
           new ArrayList<>(superMods.size());
      for (final Modification sm : superMods)
      {
        boolean add = true;
        for (final Modification m : mods)
        {
          if (m.getAttributeName().equalsIgnoreCase(sm.getAttributeName()))
          {
            add = false;
            break;
          }
        }
        if (add)
        {
          modsToAdd.add(sm);
        }
      }
      mods.addAll(modsToAdd);
    }

    return Collections.unmodifiableList(mods);
  }



  /**
   * Retrieves a filter that will match any entry containing the structural and
   * auxiliary classes for this object type.
   *
   * @return  A filter that will match any entry containing the structural and
   *          auxiliary classes for this object type.
   */
  @NotNull()
  public Filter createBaseFilter()
  {
    if (auxiliaryClasses.length == 0)
    {
      return Filter.createEqualityFilter("objectClass", structuralClass);
    }
    else
    {
      final ArrayList<Filter> comps =
           new ArrayList<>(1+auxiliaryClasses.length);
      comps.add(Filter.createEqualityFilter("objectClass", structuralClass));
      for (final String s : auxiliaryClasses)
      {
        comps.add(Filter.createEqualityFilter("objectClass", s));
      }
      return Filter.createANDFilter(comps);
    }
  }



  /**
   * Retrieves a filter that can be used to search for entries matching the
   * provided object.  It will be constructed as an AND search using all fields
   * with a non-{@code null} value and that have a {@link LDAPField} annotation
   * with the {@code inFilter} element set to {@code true}, and all  getter
   * methods that return a non-{@code null} value and have a
   * {@link LDAPGetter} annotation with the {@code inFilter} element set to
   * {@code true}.
   *
   * @param  o  The object for which to create the search filter.
   *
   * @return  A filter that can be used to search for entries matching the
   *          provided object.
   *
   * @throws  LDAPPersistException  If it is not possible to construct a search
   *                                filter for some reason (e.g., because the
   *                                provided object does not have any
   *                                non-{@code null} fields or getters that are
   *                                marked for inclusion in filters).
   */
  @NotNull()
  public Filter createFilter(@NotNull final T o)
         throws LDAPPersistException
  {
    final AtomicBoolean addedRequiredOrAllowed = new AtomicBoolean(false);

    final Filter f = createFilter(o, addedRequiredOrAllowed);
    if (! addedRequiredOrAllowed.get())
    {
      throw new LDAPPersistException(
           ERR_OBJECT_HANDLER_FILTER_MISSING_REQUIRED_OR_ALLOWED.get());
    }

    return f;
  }



  /**
   * Retrieves a filter that can be used to search for entries matching the
   * provided object.  It will be constructed as an AND search using all fields
   * with a non-{@code null} value and that have a {@link LDAPField} annotation
   * with the {@code inFilter} element set to {@code true}, and all  getter
   * methods that return a non-{@code null} value and have a
   * {@link LDAPGetter} annotation with the {@code inFilter} element set to
   * {@code true}.
   *
   * @param  o                       The object for which to create the search
   *                                 filter.
   * @param  addedRequiredOrAllowed  Indicates whether any filter elements from
   *                                 required or allowed fields or getters have
   *                                 been added to the filter yet.
   *
   * @return  A filter that can be used to search for entries matching the
   *          provided object.
   *
   * @throws  LDAPPersistException  If it is not possible to construct a search
   *                                filter for some reason (e.g., because the
   *                                provided object does not have any
   *                                non-{@code null} fields or getters that are
   *                                marked for inclusion in filters).
   */
  @NotNull()
  private Filter createFilter(@NotNull final T o,
                      @NotNull final AtomicBoolean addedRequiredOrAllowed)
          throws LDAPPersistException
  {
    final ArrayList<Attribute> attrs = new ArrayList<>(5);
    attrs.add(objectClassAttribute);

    for (final FieldInfo i : requiredFilterFields)
    {
      final Attribute a = i.encode(o, true);
      if (a == null)
      {
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_FILTER_MISSING_REQUIRED_FIELD.get(
                  i.getField().getName()));
      }
      else
      {
        attrs.add(a);
        addedRequiredOrAllowed.set(true);
      }
    }

    for (final GetterInfo i : requiredFilterGetters)
    {
      final Attribute a = i.encode(o);
      if (a == null)
      {
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_FILTER_MISSING_REQUIRED_GETTER.get(
                  i.getMethod().getName()));
      }
      else
      {
        attrs.add(a);
        addedRequiredOrAllowed.set(true);
      }
    }

    for (final FieldInfo i : alwaysAllowedFilterFields)
    {
      final Attribute a = i.encode(o, true);
      if (a != null)
      {
        attrs.add(a);
        addedRequiredOrAllowed.set(true);
      }
    }

    for (final GetterInfo i : alwaysAllowedFilterGetters)
    {
      final Attribute a = i.encode(o);
      if (a != null)
      {
        attrs.add(a);
        addedRequiredOrAllowed.set(true);
      }
    }

    for (final FieldInfo i : conditionallyAllowedFilterFields)
    {
      final Attribute a = i.encode(o, true);
      if (a != null)
      {
        attrs.add(a);
      }
    }

    for (final GetterInfo i : conditionallyAllowedFilterGetters)
    {
      final Attribute a = i.encode(o);
      if (a != null)
      {
        attrs.add(a);
      }
    }

    final ArrayList<Filter> comps = new ArrayList<>(attrs.size());
    for (final Attribute a : attrs)
    {
      for (final ASN1OctetString v : a.getRawValues())
      {
        comps.add(Filter.createEqualityFilter(a.getName(), v.getValue()));
      }
    }

    if (superclassHandler != null)
    {
      final Filter f =
           superclassHandler.createFilter(o, addedRequiredOrAllowed);
      if (f.getFilterType() == Filter.FILTER_TYPE_AND)
      {
        comps.addAll(Arrays.asList(f.getComponents()));
      }
      else
      {
        comps.add(f);
      }
    }

    return Filter.createANDFilter(comps);
  }
}
