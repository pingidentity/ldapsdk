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
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

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

import static com.unboundid.ldap.sdk.persist.PersistMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides a mechanism for validating, encoding, and decoding
 * objects marked with the {@link LDAPObject} annotation type.
 *
 * @param  <T>  The type of object handled by this class.
 */
final class LDAPObjectHandler<T>
      implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1480360011153517161L;



  // The object class attribute to include in entries that are created.
  private final Attribute objectClassAttribute;

  // The type of object handled by this class.
  private final Class<T> type;

  // The constructor to use to create a new instance of the class.
  private final Constructor<T> constructor;

  // The default parent DN for entries created from objects of the associated
  //  type.
  private final DN defaultParentDN;

  // The field that will be used to hold the DN of the entry.
  private final Field dnField;

  // The field that will be used to hold the entry contents.
  private final Field entryField;

  // The LDAPObject annotation for the associated object.
  private final LDAPObject ldapObject;

  // The list of fields for this class that should be used to construct search
  // filters.
  private final List<FieldInfo> filterFields;

  // The list of fields for this class that should be used to construct the RDN.
  private final List<FieldInfo> rdnFields;

  // The list of getters for this class that should be used to construct search
  // filters
  private final List<GetterInfo> filterGetters;

  // The list of getters for this class that should be used to construct the
  // RDN.
  private final List<GetterInfo> rdnGetters;

  // The map of attribute names to their corresponding fields.
  private final Map<String,FieldInfo> fieldMap;

  // The map of attribute names to their corresponding getter methods.
  private final Map<String,GetterInfo> getterMap;

  // The map of attribute names to their corresponding setter methods.
  private final Map<String,SetterInfo> setterMap;

  // The method that should be invoked on an object after all other decode
  // processing has been performed.
  private final Method postDecodeMethod;

  // The method that should be invoked on an object after all other encode
  // processing has been performed.
  private final Method postEncodeMethod;

  // The structural object class that should be used for entries created from
  // objects of the associated type.
  private final String structuralClass;

  // The auxiliary object classes that should should used for entries created
  // from objects of the associated type.
  private final String[] auxiliaryClasses;



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
  LDAPObjectHandler(final Class<T> type)
       throws LDAPPersistException
  {
    this.type = type;

    final TreeMap<String,FieldInfo>  fields  = new TreeMap<String,FieldInfo>();
    final TreeMap<String,GetterInfo> getters = new TreeMap<String,GetterInfo>();
    final TreeMap<String,SetterInfo> setters = new TreeMap<String,SetterInfo>();

    ldapObject = type.getAnnotation(LDAPObject.class);
    if (ldapObject == null)
    {
      throw new LDAPPersistException(
           ERR_OBJECT_HANDLER_OBJECT_NOT_ANNOTATED.get(type.getName()));
    }

    final LinkedList<String> objectClasses = new LinkedList<String>();

    String oc = ldapObject.structuralClass();
    if (oc.length() == 0)
    {
      structuralClass = getUnqualifiedClassName(type);
    }
    else
    {
      structuralClass = oc;
    }

    final StringBuilder invalidReason = new StringBuilder();
    if (PersistUtils.isValidLDAPName(structuralClass, invalidReason))
    {
      objectClasses.add(structuralClass);
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
        objectClasses.add(auxiliaryClass);
      }
      else
      {
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_INVALID_AUXILIARY_CLASS.get(type.getName(),
                  auxiliaryClass, invalidReason.toString()));
      }
    }

    objectClassAttribute = new Attribute("objectClass", objectClasses);


    final String parentDNStr = ldapObject.defaultParentDN();
    try
    {
      defaultParentDN = new DN(parentDNStr);
    }
    catch (LDAPException le)
    {
      throw new LDAPPersistException(
           ERR_OBJECT_HANDLER_INVALID_DEFAULT_PARENT.get(type.getName(),
                parentDNStr, le.getMessage()), le);
    }


    final String postDecodeMethodName = ldapObject.postDecodeMethod();
    if (postDecodeMethodName.length() > 0)
    {
      try
      {
        postDecodeMethod = type.getDeclaredMethod(postDecodeMethodName);
        postDecodeMethod.setAccessible(true);
      }
      catch (Exception e)
      {
        debugException(e);
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_INVALID_POST_DECODE_METHOD.get(type.getName(),
                  postDecodeMethodName, getExceptionMessage(e)), e);
      }
    }
    else
    {
      postDecodeMethod = null;
    }


    final String postEncodeMethodName = ldapObject.postEncodeMethod();
    if (postEncodeMethodName.length() > 0)
    {
      try
      {
        postEncodeMethod = type.getDeclaredMethod(postEncodeMethodName,
             Entry.class);
        postEncodeMethod.setAccessible(true);
      }
      catch (Exception e)
      {
        debugException(e);
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_INVALID_POST_ENCODE_METHOD.get(type.getName(),
                  postEncodeMethodName, getExceptionMessage(e)), e);
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
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPPersistException(
           ERR_OBJECT_HANDLER_NO_DEFAULT_CONSTRUCTOR.get(type.getName()), e);
    }

    Field                       tmpDNField      = null;
    Field                       tmpEntryField   = null;
    final LinkedList<FieldInfo> tmpFilterFields = new LinkedList<FieldInfo>();
    final LinkedList<FieldInfo> tmpRDNFields    = new LinkedList<FieldInfo>();
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
        final String attrName = toLowerCase(fieldInfo.getAttributeName());
        if (fields.containsKey(attrName))
        {
          throw new LDAPPersistException(ERR_OBJECT_HANDLER_ATTR_CONFLICT.get(
               type.getName(), fieldInfo.getAttributeName()));
        }
        else
        {
          fields.put(attrName, fieldInfo);
        }

        if (fieldInfo.includeInSearchFilter())
        {
          tmpFilterFields.add(fieldInfo);
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

    dnField      = tmpDNField;
    entryField   = tmpEntryField;
    filterFields = Collections.unmodifiableList(tmpFilterFields);
    rdnFields    = Collections.unmodifiableList(tmpRDNFields);

    final LinkedList<GetterInfo> tmpFilterGetters =
         new LinkedList<GetterInfo>();
    final LinkedList<GetterInfo> tmpRDNGetters = new LinkedList<GetterInfo>();
    for (final Method m : type.getDeclaredMethods())
    {
      final LDAPFieldGetter getter = m.getAnnotation(LDAPFieldGetter.class);
      final LDAPFieldSetter setter = m.getAnnotation(LDAPFieldSetter.class);

      if (getter != null)
      {
        m.setAccessible(true);

        if (setter != null)
        {
          throw new LDAPPersistException(
               ERR_OBJECT_HANDLER_CONFLICTING_METHOD_ANNOTATIONS.get(
                    type.getName(), "LDAPFieldGetter", "LDAPFieldSetter",
                    m.getName()));
        }

        final GetterInfo methodInfo = new GetterInfo(m, type);
        final String attrName = toLowerCase(methodInfo.getAttributeName());
        if (fields.containsKey(attrName) || getters.containsKey(attrName))
        {
          throw new LDAPPersistException(ERR_OBJECT_HANDLER_ATTR_CONFLICT.get(
               type.getName(), methodInfo.getAttributeName()));
        }
        else
        {
          getters.put(attrName, methodInfo);
        }

        if (methodInfo.includeInSearchFilter())
        {
          tmpFilterGetters.add(methodInfo);
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
        final String attrName = toLowerCase(methodInfo.getAttributeName());
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

    filterGetters = Collections.unmodifiableList(tmpFilterGetters);

    rdnGetters = Collections.unmodifiableList(tmpRDNGetters);
    if (rdnFields.isEmpty() && rdnGetters.isEmpty())
    {
      throw new LDAPPersistException(ERR_OBJECT_HANDLER_NO_RDN_DEFINED.get(
           type.getName()));
    }

    fieldMap  = Collections.unmodifiableMap(fields);
    getterMap = Collections.unmodifiableMap(getters);
    setterMap = Collections.unmodifiableMap(setters);
  }



  /**
   * Retrieves the type of object handled by this class.
   *
   * @return  The type of object handled by this class.
   */
  Class<T> getType()
  {
    return type;
  }



  /**
   * Retrieves the {@link LDAPObject} annotation for the associated class.
   *
   * @return  The {@code LDAPObject} annotation for the associated class.
   */
  LDAPObject getLDAPObjectAnnotation()
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
  Constructor getConstructor()
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
  Field getDNField()
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
  Field getEntryField()
  {
    return entryField;
  }



  /**
   * Retrieves the default parent DN for objects of the associated type.
   *
   * @return  The default parent DN for objects of the associated type.
   */
  DN getDefaultParentDN()
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
  String getStructuralClass()
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
  String[] getAuxiliaryClasses()
  {
    return auxiliaryClasses;
  }



  /**
   * Retrieves the DN of the entry in which the provided object is stored, if
   * available.  The entry DN will not be available if the provided object was
   * not retrieved using the persistence framework, or if the associated class
   * does not have a field marked with either the {@link LDAPDNField} or
   * {@link LDAPEntryField} annotation.
   *
   * @param  o  The object for which to retrieve the associated entry DN.
   *
   * @return  The DN of the entry in which the provided object is stored, or
   *          {@code null} if that is not available.
   *
   * @throws  LDAPPersistException  If a problem occurred while attempting to
   *                                obtain the entry DN.
   */
  String getEntryDN(final T o)
       throws LDAPPersistException
  {
    if (dnField != null)
    {
      try
      {
        final Object dnObject = dnField.get(o);
        if (dnObject != null)
        {
          return String.valueOf(dnObject);
        }
      }
      catch (Exception e)
      {
        debugException(e);
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_ERROR_ACCESSING_DN_FIELD.get(dnField.getName(),
                  type.getName(), getExceptionMessage(e)), e);
      }
    }

    final ReadOnlyEntry entry = getEntry(o);
    if (entry != null)
    {
      return entry.getDN();
    }

    return null;
  }



  /**
   * Retrieves a read-only copy of the entry that was used to initialize the
   * provided object, if available.  The entry will only be available if the
   * object was retrieved from the directory using the persistence framework and
   * the associated class has a field marked with the {@link LDAPEntryField}
   * annotation.
   *
   * @param  o  The object for which to retrieve the read-only entry.
   *
   * @return  A read-only copy of the entry that was used to initialize the
   *          provided object, or {@code null} if that is not available.
   *
   * @throws  LDAPPersistException  If a problem occurred while attempting to
   *                                obtain the entry DN.
   */
  ReadOnlyEntry getEntry(final T o)
       throws LDAPPersistException
  {
    if (entryField != null)
    {
      try
      {
        final Object entryObject = entryField.get(o);
        if (entryObject != null)
        {
          return (ReadOnlyEntry) entryObject;
        }
      }
      catch (Exception e)
      {
        debugException(e);
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_ERROR_ACCESSING_ENTRY_FIELD.get(
                  entryField.getName(), type.getName(), getExceptionMessage(e)),
             e);
      }
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
  Map<String,FieldInfo> getFields()
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
  Map<String,GetterInfo> getGetters()
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
  Map<String,SetterInfo> getSetters()
  {
    return setterMap;
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
  T decode(final Entry e)
    throws LDAPPersistException
  {
    final T o;
    try
    {
      o = constructor.newInstance();
    }
    catch (Throwable t)
    {
      debugException(t);

      if (t instanceof InvocationTargetException)
      {
        t = ((InvocationTargetException) t).getTargetException();
      }

      throw new LDAPPersistException(
           ERR_OBJECT_HANDLER_ERROR_INVOKING_CONSTRUCTOR.get(type.getName(),
                getExceptionMessage(t)), t);
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
  void decode(final T o, final Entry e)
       throws LDAPPersistException
  {
    setDNAndEntryFields(o, e);

    for (final FieldInfo i : fieldMap.values())
    {
      i.decode(o, e);
    }

    for (final SetterInfo i : setterMap.values())
    {
      i.invokeSetter(o, e);
    }

    if (postDecodeMethod != null)
    {
      try
      {
        postDecodeMethod.invoke(o);
      }
      catch (Throwable t)
      {
        debugException(t);

        if (t instanceof InvocationTargetException)
        {
          t = ((InvocationTargetException) t).getTargetException();
        }

        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_ERROR_INVOKING_POST_DECODE_METHOD.get(
                  postDecodeMethod.getName(), type.getName(),
                  getExceptionMessage(t)), t);
      }
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
  Entry encode(final T o, final String parentDN)
        throws LDAPPersistException
  {
    // Get the attributes that should be included in the entry.
    final LinkedHashMap<String,Attribute> attrMap =
         new LinkedHashMap<String,Attribute>();
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
      catch (Throwable t)
      {
        debugException(t);

        if (t instanceof InvocationTargetException)
        {
          t = ((InvocationTargetException) t).getTargetException();
        }

        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_ERROR_INVOKING_POST_ENCODE_METHOD.get(
                  postEncodeMethod.getName(), type.getName(),
                  getExceptionMessage(t)), t);
      }
    }

    setDNAndEntryFields(o, entry);

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
  private void setDNAndEntryFields(final Object o, final Entry e)
          throws LDAPPersistException
  {
    if (dnField != null)
    {
      try
      {
        dnField.set(o, e.getDN());
      }
      catch (Exception ex)
      {
        debugException(ex);
        throw new LDAPPersistException(ERR_OBJECT_HANDLER_ERROR_SETTING_DN.get(
             type.getName(), e.getDN(), dnField.getName(),
             getExceptionMessage(ex)), ex);
      }
    }

    if (entryField != null)
    {
      try
      {
        entryField.set(o, new ReadOnlyEntry(e));
      }
      catch (Exception ex)
      {
        debugException(ex);
        throw new LDAPPersistException(
             ERR_OBJECT_HANDLER_ERROR_SETTING_ENTRY.get(type.getName(),
                  entryField.getName(), getExceptionMessage(ex)), ex);
      }
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
   * @param  attrMap   A map of the attributes that will be included in the
   *                   entry and may be used to construct the RDN elements.
   *
   * @return  The entry DN for the provided object.
   *
   * @throws  LDAPPersistException  If a problem occurs while obtaining the
   *                                entry DN, or if the provided parent DN
   *                                represents an invalid DN.
   */
  String constructDN(final T o, final String parentDN,
                     final Map<String,Attribute> attrMap)
         throws LDAPPersistException
  {
    final String existingDN = getEntryDN(o);
    if (existingDN != null)
    {
      return existingDN;
    }

    final ArrayList<String> rdnNameList  = new ArrayList<String>(1);
    final ArrayList<byte[]> rdnValueList = new ArrayList<byte[]>(1);
    for (final FieldInfo i : rdnFields)
    {
      final Attribute a = attrMap.get(toLowerCase(i.getAttributeName()));
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
      final Attribute a = attrMap.get(toLowerCase(i.getAttributeName()));
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
      catch (LDAPException le)
      {
        debugException(le);
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
  List<Modification> getModifications(final T o, final boolean deleteNullValues,
                                      final String... attributes)
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

    final HashSet<String> attrSet;
    if ((attributes == null) || (attributes.length == 0))
    {
      attrSet = null;
    }
    else
    {
      attrSet = new HashSet<String>(attributes.length);
      for (final String s : attributes)
      {
        attrSet.add(toLowerCase(s));
      }
    }

    final LinkedList<Modification> mods = new LinkedList<Modification>();

    for (final Map.Entry<String,FieldInfo> e : fieldMap.entrySet())
    {
      final String attrName = toLowerCase(e.getKey());
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
      final String attrName = toLowerCase(e.getKey());
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

    return Collections.unmodifiableList(mods);
  }



  /**
   * Retrieves a filter that can be used to search for entries matching the
   * provided object.  It will be constructed as an AND search using all fields
   * with a non-{@code null} value and that have a {@link LDAPField} annotation
   * with the {@code inFilter} element set to {@code true}, and all  getter
   * methods that return a non-{@code null} value and have a
   * {@link LDAPFieldGetter} annotation with the {@code inFilter} element set to
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
  Filter createFilter(final T o)
         throws LDAPPersistException
  {
    final LinkedList<Attribute> attrs = new LinkedList<Attribute>();
    attrs.add(objectClassAttribute);

    for (final FieldInfo i : filterFields)
    {
      final Attribute a = i.encode(o, true);
      if (a != null)
      {
        attrs.add(a);
      }
    }

    for (final GetterInfo i : filterGetters)
    {
      final Attribute a = i.encode(o);
      if (a != null)
      {
        attrs.add(a);
      }
    }

    final ArrayList<Filter> comps = new ArrayList<Filter>(attrs.size());
    for (final Attribute a : attrs)
    {
      for (final ASN1OctetString v : a.getRawValues())
      {
        comps.add(Filter.createEqualityFilter(a.getName(), v.getValue()));
      }
    }

    if (comps.size() == 1)
    {
      return comps.get(0);
    }
    else
    {
      return Filter.createANDFilter(comps);
    }
  }
}
