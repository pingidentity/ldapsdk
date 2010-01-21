/*
 * Copyright 2009-2010 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2010 UnboundID Corp.
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



import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.matchingrules.CaseIgnoreStringMatchingRule;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.AttributeUsage;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.persist.PersistMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides the default implementation of an {@link LDAPFieldEncoder}
 * object that will be used when encoding and decoding fields to be written to
 * or read from an LDAP directory server.
 * <BR><BR>
 * The following basic types will be supported, with the following encodings:
 * <UL>
 *   <LI>{@code java.util.concurrent.atomic.AtomicInteger} -- Encoded using the
 *       string representation of the value</LI>
 *   <LI>{@code java.util.concurrent.atomic.AtomicLong} -- Encoded using the
 *       string representation of the value</LI>
 *   <LI>{@code java.math.BigDecimal} -- Encoded using the string representation
 *       of the value</LI>
 *   <LI>{@code java.math.BigInteger} -- Encoded using the string representation
 *       of the value</LI>
 *   <LI>{@code boolean} -- Encoded as either "TRUE" or "FALSE"</LI>
 *   <LI>{@code java.lang.Boolean} -- Encoded as either "TRUE" or "FALSE"</LI>
 *   <LI>{@code byte[]} -- Encoded as the raw bytes contained in the array</LI>
 *   <LI>{@code char[]} -- Encoded as a string containing the characters in the
 *       array</LI>
 *   <LI>{@code java.util.Date} -- Encoded using the generalized time
 *       syntax</LI>
 *   <LI>{@code com.unboundid.ldap.sdk.DN} -- Encoded using the string
 *       representation of the value</LI>
 *   <LI>{@code double} -- Encoded using the string representation of the
 *       value</LI>
 *   <LI>{@code java.lang.Double} -- Encoded using the string representation of
 *       the value</LI>
 *   <LI>{@code com.unboundid.ldap.sdk.Filter} -- Encoded using the string
 *       representation of the value</LI>
 *   <LI>{@code float} -- Encoded using the string representation of the
 *       value</LI>
 *   <LI>{@code java.lang.Float} -- Encoded using the string representation of
 *       the value</LI>
 *   <LI>{@code int} -- Encoded using the string representation of the
 *       value</LI>
 *   <LI>{@code java.lang.Integer} -- Encoded using the string representation of
 *       the value</LI>
 *   <LI>{@code com.unboundid.ldap.sdk.LDAPURL} -- Encoded using the string
 *       representation of the value</LI>
 *   <LI>{@code long -- Encoded using the string representation of the
 *       value}</LI>
 *   <LI>{@code java.lang.Long} -- Encoded using the string representation of
 *       the value</LI>
 *   <LI>{@code com.unboundid.ldap.sdk.RDN} -- Encoded using the string
 *       representation of the value</LI>
 *   <LI>{@code short} -- Encoded using the string representation of the
 *       value</LI>
 *   <LI>{@code java.lang.Short} -- Encoded using the string representation of
 *       the value</LI>
 *   <LI>{@code java.lang.String} -- Encoded using the value</LI>
 *   <LI>{@code java.lang.StringBuffer} -- Encoded using the string
 *       representation of the value</LI>
 *   <LI>{@code java.lang.StringBuilder} -- Encoded using the string
 *       representation of the value</LI>
 *   <LI>{@code java.util.UUID} -- Encoded using the string representation of
 *       the value</LI>
 * </UL>
 * In addition, arrays of all of the above types are also supported, in which
 * case each element of the array will be a separate value in the corresponding
 * LDAP attribute.  Lists (including {@code ArrayList}, {@code LinkedList}, and
 * {@code CopyOnWriteArrayList}) and sets (including {@code HashSet},
 * {@code LinkedHashSet}, {@code TreeSet}, and {@code CopyOnWriteArraySet}) of
 * the above types are also supported.
 * <BR><BR>
 * Note that you should be careful when using primitive types, since they cannot
 * be unassigned and therefore will always have a value.  When using an LDAP
 * entry to initialize an object any fields with primitive types which are
 * associated with LDAP attributes not present in the entry will have the
 * default value assigned to them in the zero-argument constructor, or will have
 * the JVM-supplied default value if no value was assigned to it in the
 * constructor.  If the associated object is converted back to an LDAP entry,
 * then those fields will be included in the entry that is generated, even if
 * they were not present in the original entry.  To avoid this problem, you can
 * use the object types rather than the primitive types (e.g.,
 * {@code java.lang.Boolean} instead of the {@code boolean} primitive), in which
 * case any fields associated with attributes that are not present in the entry
 * being de-serialized will be explicitly set to {@code null}.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DefaultLDAPFieldEncoder
       extends LDAPFieldEncoder
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4566874784628920022L;



  /**
   * Creates a new instance of this encoder.
   */
  public DefaultLDAPFieldEncoder()
  {
    super();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsType(final Type t)
  {
    final TypeInfo typeInfo = new TypeInfo(t);
    if (! typeInfo.isSupported())
    {
      return false;
    }

    final Class<?> baseClass = typeInfo.getBaseClass();

    if (supportsTypeInternal(baseClass))
    {
      return true;
    }

    final Class<?> componentType = typeInfo.getComponentType();
    if (componentType == null)
    {
      return false;
    }

    if (typeInfo.isArray())
    {
      return supportsTypeInternal(componentType);
    }

    if (typeInfo.isList())
    {
      return (isSupportedListType(baseClass) &&
           supportsTypeInternal(componentType));
    }

    if (typeInfo.isSet())
    {
      return (isSupportedSetType(baseClass) &&
           supportsTypeInternal(componentType));
    }

    return false;
  }



  /**
   * Indicates whether this LDAP field encoder supports objects of the specified
   * type.
   *
   * @param  c  The object type class for which to make the determination.
   *
   * @return  {@code true} if this field encoder supports objects of the
   *          specified type, or {@code false} if not.
   */
  private static boolean supportsTypeInternal(final Class<?> c)
  {
    if (c.equals(AtomicInteger.class) ||
        c.equals(AtomicLong.class) ||
        c.equals(BigDecimal.class) ||
        c.equals(BigInteger.class) ||
        c.equals(Boolean.class) ||
        c.equals(Boolean.TYPE) ||
        c.equals(Date.class) ||
        c.equals(DN.class) ||
        c.equals(Double.class) ||
        c.equals(Double.TYPE) ||
        c.equals(Filter.class) ||
        c.equals(Float.class) ||
        c.equals(Float.TYPE) ||
        c.equals(Integer.class) ||
        c.equals(Integer.TYPE) ||
        c.equals(LDAPURL.class) ||
        c.equals(Long.class) ||
        c.equals(Long.TYPE) ||
        c.equals(RDN.class) ||
        c.equals(Short.class) ||
        c.equals(Short.TYPE) ||
        c.equals(String.class) ||
        c.equals(StringBuffer.class) ||
        c.equals(StringBuilder.class) ||
        c.equals(UUID.class))
    {
      return true;
    }

    if (c.isArray())
    {
      final Class<?> t = c.getComponentType();
      if (t.equals(Byte.TYPE) ||
          t.equals(Character.TYPE))
      {
        return true;
      }
    }

    return false;
  }



  /**
   * Indicates whether the provided type is a supported list type.
   *
   * @param  t  The type for which to make the determination.
   *
   * @return  {@code true} if the provided type is a supported list type, or
   *          or {@code false}.
   */
  private static boolean isSupportedListType(final Class<?> t)
  {
    return (t.equals(List.class) ||
            t.equals(ArrayList.class) ||
            t.equals(LinkedList.class) ||
            t.equals(CopyOnWriteArrayList.class));
  }



  /**
   * Creates a new list of the specified type.
   *
   * @param  t     The type of list to create.
   * @param  size  The number of values that will be included in the list.
   *
   * @return  The created list, or {@code null} if it is not a supported list
   *          type.
   */
  private static List<?> createList(final Class<?> t, final int size)
  {
    if (t.equals(List.class) || t.equals(ArrayList.class))
    {
      return new ArrayList(1);
    }
    else if (t.equals(LinkedList.class))
    {
      return new LinkedList();
    }
    else if (t.equals(CopyOnWriteArrayList.class))
    {
      return new CopyOnWriteArrayList();
    }

    return null;
  }



  /**
   * Indicates whether the provided type is a supported set type.
   *
   * @param  t  The type for which to make the determination.
   *
   * @return  {@code true} if the provided type is a supported set type, or
   *          or {@code false}.
   */
  private static boolean isSupportedSetType(final Class<?> t)
  {
    return (t.equals(Set.class) ||
            t.equals(HashSet.class) ||
            t.equals(LinkedHashSet.class) ||
            t.equals(TreeSet.class) ||
            t.equals(CopyOnWriteArraySet.class));
  }



  /**
   * Creates a new set of the specified type.
   *
   * @param  t     The type of set to create.
   * @param  size  The number of values that will be included in the set.
   *
   * @return  The created list, or {@code null} if it is not a supported set
   *          type.
   */
  private static Set<?> createSet(final Class<?> t, final int size)
  {
    if (t.equals(Set.class) || t.equals(LinkedHashSet.class))
    {
      return new LinkedHashSet(1);
    }
    else if (t.equals(HashSet.class))
    {
      return new HashSet(1);
    }
    else if (t.equals(TreeSet.class))
    {
      return new TreeSet();
    }
    else if (t.equals(CopyOnWriteArraySet.class))
    {
      return new CopyOnWriteArraySet();
    }

    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public AttributeTypeDefinition constructAttributeType(final Field f,
                                      final OIDAllocator a)
         throws LDAPPersistException
  {
    final LDAPField at = f.getAnnotation(LDAPField.class);

    final String attrName;
    if (at.attribute().length() == 0)
    {
      attrName = f.getName();
    }
    else
    {
      attrName = at.attribute();
    }

    final String oid = a.allocateAttributeTypeOID(attrName);

    final TypeInfo typeInfo = new TypeInfo(f.getGenericType());
    if (! typeInfo.isSupported())
    {
      throw new LDAPPersistException(ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
           String.valueOf(typeInfo.getType())));
    }

    final boolean isSingleValued = (! supportsMultipleValues(typeInfo));

    final String syntaxOID;
    if (isSingleValued)
    {
      syntaxOID = getSyntaxOID(typeInfo.getBaseClass());
    }
    else
    {
      syntaxOID = getSyntaxOID(typeInfo.getComponentType());
    }

    return new AttributeTypeDefinition(oid, new String[] { attrName }, null,
         false, null, null, null, null, syntaxOID, isSingleValued, false, false,
         AttributeUsage.USER_APPLICATIONS, null);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public AttributeTypeDefinition constructAttributeType(final Method m,
                                      final OIDAllocator a)
         throws LDAPPersistException
  {
    final LDAPFieldGetter at = m.getAnnotation(LDAPFieldGetter.class);

    final String attrName = at.attribute();
    final String oid = a.allocateAttributeTypeOID(attrName);

    final TypeInfo typeInfo = new TypeInfo(m.getGenericReturnType());
    if (! typeInfo.isSupported())
    {
      throw new LDAPPersistException(ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
           String.valueOf(typeInfo.getType())));
    }

    final boolean isSingleValued = (! supportsMultipleValues(typeInfo));

    final String syntaxOID;
    if (isSingleValued)
    {
      syntaxOID = getSyntaxOID(typeInfo.getBaseClass());
    }
    else
    {
      syntaxOID = getSyntaxOID(typeInfo.getComponentType());
    }

    return new AttributeTypeDefinition(oid, new String[] { attrName }, null,
         false, null, null, null, null, syntaxOID, isSingleValued, false, false,
         AttributeUsage.USER_APPLICATIONS, null);
  }



  /**
   * Retrieves the syntax that should be used for the specified object type.
   *
   * @param  t  The type for which to make the determination.
   *
   * @return  The syntax that should be used for the specified object type, or
   *          {@code null} if it cannot be determined.
   */
  private static String getSyntaxOID(final Class<?> t)
  {
    if (t.equals(BigDecimal.class) ||
        t.equals(Double.class) ||
        t.equals(Double.TYPE) ||
        t.equals(Float.class) ||
        t.equals(Float.TYPE) ||
        t.equals(String.class) ||
        t.equals(StringBuffer.class) ||
        t.equals(StringBuilder.class) ||
        t.equals(Filter.class) ||
        t.equals(LDAPURL.class))
    {
      return "1.3.6.1.4.1.1466.115.121.1.15";
    }
    else if (t.equals(AtomicInteger.class) ||
        t.equals(AtomicLong.class) ||
        t.equals(BigInteger.class) ||
        t.equals(Integer.class) ||
        t.equals(Integer.TYPE) ||
        t.equals(Long.class) ||
        t.equals(Long.TYPE) ||
        t.equals(Short.class) ||
        t.equals(Short.TYPE))
    {
      return "1.3.6.1.4.1.1466.115.121.1.27";
    }
    else if (t.equals(UUID.class))
    {
      // Although "1.3.6.1.1.16.1" (which is the UUID syntax as defined in RFC
      // 4530) might be more correct, some servers may not support this syntax
      // since it is relatively new, so we'll fall back on the more
      // widely-supported directory string syntax.
      return "1.3.6.1.4.1.1466.115.121.1.15";
    }
    else if (t.equals(DN.class) ||
             t.equals(RDN.class))
    {
      return "1.3.6.1.4.1.1466.115.121.1.12";
    }
    else if (t.equals(Boolean.class) ||
             t.equals(Boolean.TYPE))
    {
      return "1.3.6.1.4.1.1466.115.121.1.7";
    }
    else if (t.equals(Date.class))
    {
      return "1.3.6.1.4.1.1466.115.121.1.24";
    }
    else if (t.isArray())
    {
      final Class<?> ct = t.getComponentType();
      if (ct.equals(Byte.TYPE))
      {
        return "1.3.6.1.4.1.1466.115.121.1.40";
      }
      else if (ct.equals(Character.TYPE))
      {
        return "1.3.6.1.4.1.1466.115.121.1.15";
      }
    }

    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsMultipleValues(final Field field)
  {
    return supportsMultipleValues(new TypeInfo(field.getGenericType()));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsMultipleValues(final Method method)
  {
    final Type[] paramTypes = method.getGenericParameterTypes();
    if (paramTypes.length != 1)
    {
      return false;
    }

    return supportsMultipleValues(new TypeInfo(paramTypes[0]));
  }



  /**
   * Indicates whether the provided object type supports multiple values.
   *
   * @param  t  The type for which to make the determination.
   *
   * @return  {@code true} if the provided object type supports multiple values,
   *          or {@code false} if not.
   */
  private static boolean supportsMultipleValues(final TypeInfo t)
  {
    if (t.isArray())
    {
      final Class<?> componentType = t.getComponentType();
      return (! (componentType.equals(Byte.TYPE) ||
                 componentType.equals(Character.TYPE)));
    }
    else
    {
      return t.isMultiValued();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Attribute encodeFieldValue(final Field field, final Object value,
                                    final String name)
         throws LDAPPersistException
  {
    return encodeValue(field.getGenericType(), value, name);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Attribute encodeMethodValue(final Method method, final Object value,
                                     final String name)
         throws LDAPPersistException
  {
    return encodeValue(method.getGenericReturnType(), value, name);
  }



  /**
   * Encodes the provided value to an LDAP attribute.
   *
   * @param  type   The type for the provided value.
   * @param  value  The value for the field in the object to be encoded.
   * @param  name   The name to use for the constructed attribute.
   *
   * @return  The attribute containing the encoded representation of the
   *          provided field.
   *
   * @throws  LDAPPersistException  If a problem occurs while attempting to
   *                                construct an attribute for the field.
   */
  private static Attribute encodeValue(final Type type, final Object value,
                                       final String name)
         throws LDAPPersistException
  {
    final TypeInfo typeInfo = new TypeInfo(type);

    final Class<?> c = typeInfo.getBaseClass();
    if (c.equals(AtomicInteger.class) ||
        c.equals(AtomicLong.class) ||
        c.equals(BigDecimal.class) ||
        c.equals(BigInteger.class) ||
        c.equals(Double.class) ||
        c.equals(Double.TYPE) ||
        c.equals(Float.class) ||
        c.equals(Float.TYPE) ||
        c.equals(Integer.class) ||
        c.equals(Integer.TYPE) ||
        c.equals(Long.class) ||
        c.equals(Long.TYPE) ||
        c.equals(Short.class) ||
        c.equals(Short.TYPE) ||
        c.equals(String.class) ||
        c.equals(StringBuffer.class) ||
        c.equals(StringBuilder.class) ||
        c.equals(UUID.class) ||
        c.equals(DN.class) ||
        c.equals(Filter.class) ||
        c.equals(LDAPURL.class) ||
        c.equals(RDN.class))
    {
      return new Attribute(name, String.valueOf(value));
    }
    else if (value instanceof byte[])
    {
      return new Attribute(name, (byte[]) value);
    }
    else if (value instanceof char[])
    {
      return new Attribute(name, new String((char[]) value));
    }
    else if (c.equals(Boolean.class) || c.equals(Boolean.TYPE))
    {
      final Boolean b = (Boolean) value;
      if (b)
      {
        return new Attribute(name, "TRUE");
      }
      else
      {
        return new Attribute(name, "FALSE");
      }
    }
    else if (c.equals(Date.class))
    {
      final Date d = (Date) value;
      return new Attribute(name, encodeGeneralizedTime(d));
    }
    else if (typeInfo.isArray())
    {
      return encodeArray(typeInfo.getComponentType(), value, name);
    }
    else if (Collection.class.isAssignableFrom(c))
    {
      return encodeCollection(typeInfo.getComponentType(),
           (Collection<?>) value, name);
    }

    throw new LDAPPersistException(ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
         String.valueOf(type)));
  }



  /**
   * Encodes the contents of the provided array object.
   *
   * @param  arrayType      The component type of the array.
   * @param  arrayObject    The array object to process.
   * @param  attributeName  The name to use for the attribute to create.
   *
   * @return  The attribute containing the encoded array contents.
   *
   * @throws  LDAPPersistException  If a problem occurs while trying to create
   *                                the attribute.
   */
  private static Attribute encodeArray(final Class<?> arrayType,
                                       final Object arrayObject,
                                       final String attributeName)
          throws LDAPPersistException
  {
    final ASN1OctetString[] values =
         new ASN1OctetString[Array.getLength(arrayObject)];
    for (int i=0; i < values.length; i++)
    {
      final Object o = Array.get(arrayObject, i);
      if (arrayType.equals(AtomicInteger.class) ||
          arrayType.equals(AtomicLong.class) ||
          arrayType.equals(BigDecimal.class) ||
          arrayType.equals(BigInteger.class) ||
          arrayType.equals(Double.class) ||
          arrayType.equals(Double.TYPE) ||
          arrayType.equals(Float.class) ||
          arrayType.equals(Float.TYPE) ||
          arrayType.equals(Integer.class) ||
          arrayType.equals(Integer.TYPE) ||
          arrayType.equals(Long.class) ||
          arrayType.equals(Long.TYPE) ||
          arrayType.equals(Short.class) ||
          arrayType.equals(Short.TYPE) ||
          arrayType.equals(String.class) ||
          arrayType.equals(StringBuffer.class) ||
          arrayType.equals(StringBuilder.class) ||
          arrayType.equals(UUID.class) ||
          arrayType.equals(DN.class) ||
          arrayType.equals(Filter.class) ||
          arrayType.equals(LDAPURL.class) ||
          arrayType.equals(RDN.class))
      {
        values[i] = new ASN1OctetString(String.valueOf(o));
      }
      else if (o instanceof byte[])
      {
        values[i] = new ASN1OctetString((byte[]) o);
      }
      else if (o instanceof char[])
      {
        values[i] = new ASN1OctetString(new String((char[]) o));
      }
      else if (arrayType.equals(Boolean.class) ||
               arrayType.equals(Boolean.TYPE))
      {
        final Boolean b = (Boolean) o;
        if (b)
        {
          values[i] = new ASN1OctetString("TRUE");
        }
        else
        {
          values[i] = new ASN1OctetString("FALSE");
        }
      }
      else if (arrayType.equals(Date.class))
      {
        final Date d = (Date) o;
        values[i] = new ASN1OctetString(encodeGeneralizedTime(d));
      }
      else
      {
        throw new LDAPPersistException(ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
             arrayType.getName()));
      }
    }

    return new Attribute(attributeName,
         CaseIgnoreStringMatchingRule.getInstance(), values);
  }



  /**
   * Encodes the contents of the provided collection.
   *
   * @param  genericType    The generic type of the collection.
   * @param  collection     The collection to process.
   * @param  attributeName  The name to use for the attribute to create.
   *
   * @return  The attribute containing the encoded collection contents.
   *
   * @throws  LDAPPersistException  If a problem occurs while trying to create
   *                                the attribute.
   */
  private static Attribute encodeCollection(final Class<?> genericType,
                                            final Collection<?> collection,
                                            final String attributeName)
          throws LDAPPersistException
  {
    final ASN1OctetString[] values = new ASN1OctetString[collection.size()];

    int i=0;
    for (final Object o : collection)
    {
      if (genericType.equals(AtomicInteger.class) ||
          genericType.equals(AtomicLong.class) ||
          genericType.equals(BigDecimal.class) ||
          genericType.equals(BigInteger.class) ||
          genericType.equals(Double.class) ||
          genericType.equals(Double.TYPE) ||
          genericType.equals(Float.class) ||
          genericType.equals(Float.TYPE) ||
          genericType.equals(Integer.class) ||
          genericType.equals(Integer.TYPE) ||
          genericType.equals(Long.class) ||
          genericType.equals(Long.TYPE) ||
          genericType.equals(Short.class) ||
          genericType.equals(Short.TYPE) ||
          genericType.equals(String.class) ||
          genericType.equals(StringBuffer.class) ||
          genericType.equals(StringBuilder.class) ||
          genericType.equals(UUID.class) ||
          genericType.equals(DN.class) ||
          genericType.equals(Filter.class) ||
          genericType.equals(LDAPURL.class) ||
          genericType.equals(RDN.class))
      {
        values[i] = new ASN1OctetString(String.valueOf(o));
      }
      else if (o instanceof byte[])
      {
        values[i] = new ASN1OctetString((byte[]) o);
      }
      else if (o instanceof char[])
      {
        values[i] = new ASN1OctetString(new String((char[]) o));
      }
      else if (genericType.equals(Boolean.class) ||
               genericType.equals(Boolean.TYPE))
      {
        final Boolean b = (Boolean) o;
        if (b)
        {
          values[i] = new ASN1OctetString("TRUE");
        }
        else
        {
          values[i] = new ASN1OctetString("FALSE");
        }
      }
      else if (genericType.equals(Date.class))
      {
        final Date d = (Date) o;
        values[i] = new ASN1OctetString(encodeGeneralizedTime(d));
      }
      else
      {
        throw new LDAPPersistException(ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
             genericType.getName()));
      }

      i++;
    }

    return new Attribute(attributeName,
         CaseIgnoreStringMatchingRule.getInstance(), values);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void decodeField(final Field field, final Object object,
                          final Attribute attribute)
         throws LDAPPersistException
  {
    field.setAccessible(true);
    final TypeInfo typeInfo = new TypeInfo(field.getGenericType());

    try
    {
      final Class<?> baseClass = typeInfo.getBaseClass();
      final Object newValue = getValue(baseClass, attribute, 0);
      if (newValue != null)
      {
        field.set(object, newValue);
        return;
      }

      if (typeInfo.isArray())
      {
        final Class<?> componentType = typeInfo.getComponentType();
        final ASN1OctetString[] values = attribute.getRawValues();
        final Object arrayObject =
             Array.newInstance(componentType, values.length);
        for (int i=0; i < values.length; i++)
        {
          final Object o = getValue(componentType, attribute, i);
          if (o == null)
          {
            throw new LDAPPersistException(
                 ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
                      componentType.getName()));
          }
          Array.set(arrayObject, i, o);
        }

        field.set(object, arrayObject);
        return;
      }
      else if (typeInfo.isList() && isSupportedListType(baseClass))
      {
        final Class<?> componentType = typeInfo.getComponentType();
        if (componentType == null)
        {
          throw new LDAPPersistException(
               ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(baseClass.getName()));
        }

        final ASN1OctetString[] values = attribute.getRawValues();
        final List<?> l = createList(baseClass, values.length);
        for (int i=0; i < values.length; i++)
        {
          final Object o = getValue(componentType, attribute, i);
          if (o == null)
          {
            throw new LDAPPersistException(
                 ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
                      componentType.getName()));
          }

          invokeAdd(l, o);
        }

        field.set(object, l);
        return;
      }
      else if (typeInfo.isSet() && isSupportedSetType(baseClass))
      {
        final Class<?> componentType = typeInfo.getComponentType();
        if (componentType == null)
        {
          throw new LDAPPersistException(
               ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(baseClass.getName()));
        }

        final ASN1OctetString[] values = attribute.getRawValues();
        final Set<?> l = createSet(baseClass, values.length);
        for (int i=0; i < values.length; i++)
        {
          final Object o = getValue(componentType, attribute, i);
          if (o == null)
          {
            throw new LDAPPersistException(
                 ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
                      componentType.getName()));
          }

          invokeAdd(l, o);
        }

        field.set(object, l);
        return;
      }

      throw new LDAPPersistException(ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
           baseClass.getName()));
    }
    catch (LDAPPersistException lpe)
    {
      debugException(lpe);
      throw lpe;
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPPersistException(getExceptionMessage(e), e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void invokeSetter(final Method method, final Object object,
                           final Attribute attribute)
         throws LDAPPersistException
  {
    final TypeInfo typeInfo =
         new TypeInfo(method.getGenericParameterTypes()[0]);
    final Class<?> baseClass = typeInfo.getBaseClass();
    method.setAccessible(true);

    try
    {
      final Object newValue = getValue(baseClass, attribute, 0);
      if (newValue != null)
      {
        method.invoke(object, newValue);
        return;
      }

      if (typeInfo.isArray())
      {
        final Class<?> componentType = typeInfo.getComponentType();
        final ASN1OctetString[] values = attribute.getRawValues();
        final Object arrayObject =
             Array.newInstance(componentType, values.length);
        for (int i=0; i < values.length; i++)
        {
          final Object o = getValue(componentType, attribute, i);
          if (o == null)
          {
            throw new LDAPPersistException(
                 ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
                      componentType.getName()));
          }
          Array.set(arrayObject, i, o);
        }

        method.invoke(object, arrayObject);
        return;
      }
      else if (typeInfo.isList() && isSupportedListType(baseClass))
      {
        final Class<?> componentType = typeInfo.getComponentType();
        if (componentType == null)
        {
          throw new LDAPPersistException(
               ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(baseClass.getName()));
        }

        final ASN1OctetString[] values = attribute.getRawValues();
        final List<?> l = createList(baseClass, values.length);
        for (int i=0; i < values.length; i++)
        {
          final Object o = getValue(componentType, attribute, i);
          if (o == null)
          {
            throw new LDAPPersistException(
                 ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
                      componentType.getName()));
          }

          invokeAdd(l, o);
        }

        method.invoke(object, l);
        return;
      }
      else if (typeInfo.isSet() && isSupportedSetType(baseClass))
      {
        final Class<?> componentType = typeInfo.getComponentType();
        if (componentType == null)
        {
          throw new LDAPPersistException(
               ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(baseClass.getName()));
        }

        final ASN1OctetString[] values = attribute.getRawValues();
        final Set<?> s = createSet(baseClass, values.length);
        for (int i=0; i < values.length; i++)
        {
          final Object o = getValue(componentType, attribute, i);
          if (o == null)
          {
            throw new LDAPPersistException(
                 ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
                      componentType.getName()));
          }

          invokeAdd(s, o);
        }

        method.invoke(object, s);
        return;
      }

      throw new LDAPPersistException(ERR_DEFAULT_ENCODER_UNSUPPORTED_TYPE.get(
           baseClass.getName()));
    }
    catch (LDAPPersistException lpe)
    {
      debugException(lpe);
      throw lpe;
    }
    catch (Throwable t)
    {
      debugException(t);

      if (t instanceof InvocationTargetException)
      {
        t = ((InvocationTargetException) t).getTargetException();
      }

      throw new LDAPPersistException(getExceptionMessage(t), t);
    }
  }



  /**
   * Creates an object of the specified type from the given attribute value.
   *
   * @param  t  The type of object to create.
   * @param  a  The attribute to use to create the object.
   * @param  p  The position in the set of values for the object to create.
   *
   * @return  The created object, or {@code null} if the provided type is not
   *          supported.
   *
   * @throws  LDAPPersistException  If a problem occurs while creating the
   *                                object.
   */
  private static Object getValue(final Class<?> t, final Attribute a,
                                 final int p)
          throws LDAPPersistException
  {
    final ASN1OctetString v = a.getRawValues()[p];

    if (t.equals(AtomicInteger.class))
    {
      return new AtomicInteger(Integer.valueOf(v.stringValue()));
    }
    else if (t.equals(AtomicLong.class))
    {
      return new AtomicLong(Long.valueOf(v.stringValue()));
    }
    else if (t.equals(BigDecimal.class))
    {
      return new BigDecimal(v.stringValue());
    }
    else if (t.equals(BigInteger.class))
    {
      return new BigInteger(v.stringValue());
    }
    else if (t.equals(Double.class) || t.equals(Double.TYPE))
    {
      return Double.valueOf(v.stringValue());
    }
    else if (t.equals(Float.class) || t.equals(Float.TYPE))
    {
      return Float.valueOf(v.stringValue());
    }
    else if (t.equals(Integer.class) || t.equals(Integer.TYPE))
    {
      return Integer.valueOf(v.stringValue());
    }
    else if (t.equals(Long.class) || t.equals(Long.TYPE))
    {
      return Long.valueOf(v.stringValue());
    }
    else if (t.equals(Short.class) || t.equals(Short.TYPE))
    {
      return Short.valueOf(v.stringValue());
    }
    else if (t.equals(String.class))
    {
      return String.valueOf(v.stringValue());
    }
    else if (t.equals(StringBuffer.class))
    {
      return new StringBuffer(v.stringValue());
    }
    else if (t.equals(StringBuilder.class))
    {
      return new StringBuilder(v.stringValue());
    }
    else if (t.equals(UUID.class))
    {
      try
      {
        return UUID.fromString(v.stringValue());
      }
      catch (Exception e)
      {
        debugException(e);
        throw new LDAPPersistException(
             ERR_DEFAULT_ENCODER_VALUE_INVALID_UUID.get(v.stringValue(),
                  getExceptionMessage(e)), e);
      }
    }
    else if (t.equals(DN.class))
    {
      try
      {
        return new DN(v.stringValue());
      }
      catch (LDAPException le)
      {
        debugException(le);
        throw new LDAPPersistException(le.getMessage(), le);
      }
    }
    else if (t.equals(Filter.class))
    {
      try
      {
        return Filter.create(v.stringValue());
      }
      catch (LDAPException le)
      {
        debugException(le);
        throw new LDAPPersistException(le.getMessage(), le);
      }
    }
    else if (t.equals(LDAPURL.class))
    {
      try
      {
        return new LDAPURL(v.stringValue());
      }
      catch (LDAPException le)
      {
        debugException(le);
        throw new LDAPPersistException(le.getMessage(), le);
      }
    }
    else if (t.equals(RDN.class))
    {
      try
      {
        return new RDN(v.stringValue());
      }
      catch (LDAPException le)
      {
        debugException(le);
        throw new LDAPPersistException(le.getMessage(), le);
      }
    }
    else if (t.equals(Boolean.class) || t.equals(Boolean.TYPE))
    {
      final String s = v.stringValue();
      if (s.equalsIgnoreCase("TRUE"))
      {
        return Boolean.TRUE;
      }
      else if (s.equalsIgnoreCase("FALSE"))
      {
        return Boolean.FALSE;
      }
      else
      {
        throw new LDAPPersistException(
             ERR_DEFAULT_ENCODER_VALUE_INVALID_BOOLEAN.get(s));
      }
    }
    else if (t.equals(Date.class))
    {
      try
      {
        return decodeGeneralizedTime(v.stringValue());
      }
      catch (Exception e)
      {
        debugException(e);
        throw new LDAPPersistException(
             ERR_DEFAULT_ENCODER_VALUE_INVALID_DATE.get(v.stringValue(),
                  e.getMessage()), e);
      }
    }
    else if (t.isArray())
    {
      final Class<?> componentType = t.getComponentType();
      if (componentType.equals(Byte.TYPE))
      {
        return v.getValue();
      }
      else if (componentType.equals(Character.TYPE))
      {
        return v.stringValue().toCharArray();
      }
    }

    return null;
  }



  /**
   * Invokes the {@code add} method on the provided {@code List} or {@code Set}
   * object.
   *
   * @param  l  The list or set on which to invoke the {@code add} method.
   * @param  o  The object to add to the {@code List} or {@code Set} object.
   *
   * @throws  LDAPPersistException  If a problem occurs while attempting to
   *                                invoke the {@code add} method.
   */
  private static void invokeAdd(final Object l, final Object o)
          throws LDAPPersistException
  {
    final Class<?> c = l.getClass();

    for (final Method m : c.getMethods())
    {
      if (m.getName().equals("add") &&
          (m.getGenericParameterTypes().length == 1))
      {
        try
        {
          m.invoke(l, o);
          return;
        }
        catch (final Exception e)
        {
          debugException(e);
          throw new LDAPPersistException(
               ERR_DEFAULT_ENCODER_CANNOT_ADD.get(getExceptionMessage(e)), e);
        }
      }
    }

    throw new LDAPPersistException(
         ERR_DEFAULT_ENCODER_CANNOT_FIND_ADD_METHOD.get());
  }
}