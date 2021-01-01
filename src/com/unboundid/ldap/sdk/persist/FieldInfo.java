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
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.List;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
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
 * annotated field.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class FieldInfo
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5715642176677596417L;



  // Indicates whether attempts to populate the associated field should fail if
  // the LDAP attribute has a value that is not valid for the data type of the
  // field.
  private final boolean failOnInvalidValue;

  // Indicates whether attempts to populate the associated field should fail if
  // the LDAP attribute has multiple values but the field can only hold a single
  // value.
  private final boolean failOnTooManyValues;

  // Indicates whether the associated field should be included in the entry
  // created for an add operation.
  private final boolean includeInAdd;

  // Indicates whether the associated field should be considered for inclusion
  // in the set of modifications used for modify operations.
  private final boolean includeInModify;

  // Indicates whether the associated field is part of the RDN.
  private final boolean includeInRDN;

  // Indicates whether the associated field is required when decoding.
  private final boolean isRequiredForDecode;

  // Indicates whether the associated field is required when encoding.
  private final boolean isRequiredForEncode;

  // Indicates whether the associated field should be lazily-loaded.
  private final boolean lazilyLoad;

  // Indicates whether the associated field supports multiple values.
  private final boolean supportsMultipleValues;

  // The class that contains the associated field.
  @NotNull private final Class<?> containingClass;

  // The field with which this object is associated.
  @NotNull private final Field field;

  // The filter usage for the associated field.
  @NotNull private final FilterUsage filterUsage;

  // The encoder used for this field.
  @NotNull private final ObjectEncoder encoder;

  // The name of the associated attribute type.
  @NotNull private final String attributeName;

  // The default values for the field to use for object instantiation.
  @NotNull private final String[] defaultDecodeValues;

  // The default values for the field to use for add operations.
  @NotNull private final String[] defaultEncodeValues;

  // The names of the object classes for the associated attribute.
  @NotNull private final String[] objectClasses;



  /**
   * Creates a new field info object from the provided field.
   *
   * @param  f  The field to use to create this object.  It must not be
   *            {@code null} and it must be marked with the {@code LDAPField}
   *            annotation.
   * @param  c  The class which holds the field.  It must not be {@code null}
   *            and it must be marked with the {@code LDAPObject} annotation.
   *
   * @throws  LDAPPersistException  If a problem occurs while processing the
   *                                given field.
   */
  FieldInfo(@NotNull final Field f, @NotNull final Class<?> c)
       throws LDAPPersistException
  {
    Validator.ensureNotNull(f, c);

    field = f;
    f.setAccessible(true);

    final LDAPField  a = f.getAnnotation(LDAPField.class);
    if (a == null)
    {
      throw new LDAPPersistException(ERR_FIELD_INFO_FIELD_NOT_ANNOTATED.get(
           f.getName(), c.getName()));
    }

    final LDAPObject o = c.getAnnotation(LDAPObject.class);
    if (o == null)
    {
      throw new LDAPPersistException(ERR_FIELD_INFO_CLASS_NOT_ANNOTATED.get(
           c.getName()));
    }

    containingClass     = c;
    failOnInvalidValue  = a.failOnInvalidValue();
    includeInRDN        = a.inRDN();
    includeInAdd        = (includeInRDN || a.inAdd());
    includeInModify     = ((! includeInRDN) && a.inModify());
    filterUsage         = a.filterUsage();
    lazilyLoad          = a.lazilyLoad();
    isRequiredForDecode = (a.requiredForDecode() && (! lazilyLoad));
    isRequiredForEncode = (includeInRDN || a.requiredForEncode());
    defaultDecodeValues = a.defaultDecodeValue();
    defaultEncodeValues = a.defaultEncodeValue();

    if (lazilyLoad)
    {
      if (defaultDecodeValues.length > 0)
      {
        throw new LDAPPersistException(
             ERR_FIELD_INFO_LAZY_WITH_DEFAULT_DECODE.get(f.getName(),
                  c.getName()));
      }

      if (defaultEncodeValues.length > 0)
      {
        throw new LDAPPersistException(
             ERR_FIELD_INFO_LAZY_WITH_DEFAULT_ENCODE.get(f.getName(),
                  c.getName()));
      }

      if (includeInRDN)
      {
        throw new LDAPPersistException(ERR_FIELD_INFO_LAZY_IN_RDN.get(
             f.getName(), c.getName()));
      }
    }

    final int modifiers = f.getModifiers();
    if (Modifier.isFinal(modifiers))
    {
      throw new LDAPPersistException(ERR_FIELD_INFO_FIELD_FINAL.get(
           f.getName(), c.getName()));
    }

    if (Modifier.isStatic(modifiers))
    {
      throw new LDAPPersistException(ERR_FIELD_INFO_FIELD_STATIC.get(
           f.getName(), c.getName()));
    }

    try
    {
      encoder = a.encoderClass().newInstance();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPPersistException(ERR_FIELD_INFO_CANNOT_GET_ENCODER.get(
           a.encoderClass().getName(), f.getName(), c.getName(),
           StaticUtils.getExceptionMessage(e)), e);
    }

    if (! encoder.supportsType(f.getGenericType()))
    {
      throw new LDAPPersistException(
           ERR_FIELD_INFO_ENCODER_UNSUPPORTED_TYPE.get(
                encoder.getClass().getName(), f.getName(), c.getName(),
                f.getGenericType()));
    }

    supportsMultipleValues = encoder.supportsMultipleValues(f);
    if (supportsMultipleValues)
    {
      failOnTooManyValues = false;
    }
    else
    {
      failOnTooManyValues = a.failOnTooManyValues();
      if (defaultDecodeValues.length > 1)
      {
        throw new LDAPPersistException(
             ERR_FIELD_INFO_UNSUPPORTED_MULTIPLE_DEFAULT_DECODE_VALUES.get(
                  f.getName(), c.getName()));
      }

      if (defaultEncodeValues.length > 1)
      {
        throw new LDAPPersistException(
             ERR_FIELD_INFO_UNSUPPORTED_MULTIPLE_DEFAULT_ENCODE_VALUES.get(
                  f.getName(), c.getName()));
      }
    }

    final String attrName = a.attribute();
    if ((attrName == null) || attrName.isEmpty())
    {
      attributeName = f.getName();
    }
    else
    {
      attributeName = attrName;
    }

    final StringBuilder invalidReason = new StringBuilder();
    if (! PersistUtils.isValidLDAPName(attributeName, true, invalidReason))
    {
      throw new LDAPPersistException(ERR_FIELD_INFO_INVALID_ATTR_NAME.get(
           f.getName(), c.getName(), invalidReason.toString()));
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
          throw new LDAPPersistException(ERR_FIELD_INFO_INVALID_OC.get(
               f.getName(), c.getName(), s));
        }
      }
    }
  }



  /**
   * Retrieves the field with which this object is associated.
   *
   * @return  The field with which this object is associated.
   */
  @NotNull()
  public Field getField()
  {
    return field;
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
   * attribute has a value that cannot be stored in the associated field.
   *
   * @return  {@code true} if an exception should be thrown if an LDAP attribute
   *          has a value that cannot be assigned to the associated field, or
   *          {@code false} if the field should remain uninitialized.
   */
  public boolean failOnInvalidValue()
  {
    return failOnInvalidValue;
  }



  /**
   * Indicates whether attempts to initialize an object should fail if the
   * LDAP attribute has multiple values but the associated field can only hold a
   * single value.  Note that the value returned from this method may be
   * {@code false} even when the annotation has a value of {@code true} if the
   * associated field supports multiple values.
   *
   * @return  {@code true} if an exception should be thrown if an attribute has
   *          too many values to hold in the associated field, or {@code false}
   *          if the first value returned should be assigned to the field.
   */
  public boolean failOnTooManyValues()
  {
    return failOnTooManyValues;
  }



  /**
   * Indicates whether the associated field should be included in entries
   * generated for add operations.  Note that the value returned from this
   * method may be {@code true} even when the annotation has a value of
   * {@code false} if the associated field is to be included in entry RDNs.
   *
   * @return  {@code true} if the associated field should be included in entries
   *         generated for add operations, or {@code false} if not.
   */
  public boolean includeInAdd()
  {
    return includeInAdd;
  }



  /**
   * Indicates whether the associated field should be considered for inclusion
   * in the set of modifications generated for modify operations.  Note that the
   * value returned from this method may be {@code false} even when the
   * annotation has a value of {@code true} for the {@code inModify} element if
   * the associated field is to be included in entry RDNs.
   *
   * @return  {@code true} if the associated field should be considered for
   *          inclusion in the set of modifications generated for modify
   *          operations, or {@code false} if not.
   */
  public boolean includeInModify()
  {
    return includeInModify;
  }



  /**
   * Indicates whether the associated field should be used to generate entry
   * RDNs.
   *
   * @return  {@code true} if the associated field should be used to generate
   *          entry RDNs, or {@code false} if not.
   */
  public boolean includeInRDN()
  {
    return includeInRDN;
  }



  /**
   * Retrieves the filter usage for the associated field.
   *
   * @return  The filter usage for the associated field.
   */
  @NotNull()
  public FilterUsage getFilterUsage()
  {
    return filterUsage;
  }



  /**
   * Indicates whether the associated field should be considered required for
   * decode operations.
   *
   * @return  {@code true} if the associated field should be considered required
   *          for decode operations, or {@code false} if not.
   */
  public boolean isRequiredForDecode()
  {
    return isRequiredForDecode;
  }



  /**
   * Indicates whether the associated field should be considered required for
   * encode operations.  Note that the value returned from this method may be
   * {@code true} even when the annotation has a value of {@code true} for the
   * {@code requiredForEncode} element if the associated field is to be included
   * in entry RDNs.
   *
   * @return  {@code true} if the associated field should be considered required
   *          for encode operations, or {@code false} if not.
   */
  public boolean isRequiredForEncode()
  {
    return isRequiredForEncode;
  }



  /**
   * Indicates whether the associated field should be lazily-loaded.
   *
   * @return  {@code true} if the associated field should be lazily-loaded, or
   *          {@code false} if not.
   */
  public boolean lazilyLoad()
  {
    return lazilyLoad;
  }



  /**
   * Retrieves the encoder that should be used for the associated field.
   *
   * @return  The encoder that should be used for the associated field.
   */
  @NotNull()
  public ObjectEncoder getEncoder()
  {
    return encoder;
  }



  /**
   * Retrieves the name of the LDAP attribute used to hold values for the
   * associated field.
   *
   * @return  The name of the LDAP attribute used to hold values for the
   *          associated field.
   */
  @NotNull()
  public String getAttributeName()
  {
    return attributeName;
  }



  /**
   * Retrieves the set of default values that should be assigned to the
   * associated field if there are no values for the corresponding attribute in
   * the LDAP entry.
   *
   * @return  The set of default values for use when instantiating the object,
   *          or an empty array if no default values are defined.
   */
  @NotNull()
  public String[] getDefaultDecodeValues()
  {
    return defaultDecodeValues;
  }



  /**
   * Retrieves the set of default values that should be used when creating an
   * entry for an add operation if the associated field does not itself have any
   * values.
   *
   * @return  The set of default values for use in add operations, or an empty
   *          array if no default values are defined.
   */
  @NotNull()
  public String[] getDefaultEncodeValues()
  {
    return defaultEncodeValues;
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
   * Indicates whether the associated field can hold multiple values.
   *
   * @return  {@code true} if the associated field can hold multiple values, or
   *          {@code false} if not.
   */
  public boolean supportsMultipleValues()
  {
    return supportsMultipleValues;
  }



  /**
   * Constructs a definition for an LDAP attribute type which may be added to
   * the directory server schema to allow it to hold the value of the associated
   * field.  Note that the object identifier used for the constructed attribute
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
   * field.  Note that the object identifier used for the constructed attribute
   * type definition is not required to be valid or unique.
   *
   * @param  a  The OID allocator to use to generate the object identifier.  It
   *            must not be {@code null}.
   *
   * @return  The constructed attribute type definition.
   *
   * @throws  LDAPPersistException  If the object encoder does not support
   *                                encoding values for the associated field
   *                                type.
   */
  @NotNull()
  AttributeTypeDefinition constructAttributeType(@NotNull final OIDAllocator a)
       throws LDAPPersistException
  {
    return encoder.constructAttributeType(field, a);
  }



  /**
   * Encodes the value for the associated field from the provided object to an
   * attribute.
   *
   * @param  o                   The object containing the field to be encoded.
   * @param  ignoreRequiredFlag  Indicates whether to ignore the value of the
   *                             {@code requiredForEncode} setting.  If this is
   *                             {@code true}, then this method will always
   *                             return {@code null} if the field does not have
   *                             a value even if this field is marked as
   *                             required for encode processing.
   *
   * @return  The attribute containing the encoded representation of the field
   *          value if it is non-{@code null}, an encoded representation of the
   *          default add values if the associated field is {@code null} but
   *          default values are defined, or {@code null} if the associated
   *          field is {@code null} and there are no default values.
   *
   * @throws  LDAPPersistException  If a problem occurs while encoding the
   *                                value of the associated field for the
   *                                provided object, or if the field is marked
   *                                as required but is {@code null} and does not
   *                                have any default add values.
   */
  @Nullable()
  Attribute encode(@NotNull final Object o, final boolean ignoreRequiredFlag)
            throws LDAPPersistException
  {
    try
    {
      final Object fieldValue = field.get(o);
      if (fieldValue == null)
      {
        if (defaultEncodeValues.length > 0)
        {
          return new Attribute(attributeName, defaultEncodeValues);
        }

        if (isRequiredForEncode && (! ignoreRequiredFlag))
        {
          throw new LDAPPersistException(
               ERR_FIELD_INFO_MISSING_REQUIRED_VALUE.get(field.getName(),
                    containingClass.getName()));
        }

        return null;
      }

      return encoder.encodeFieldValue(field, fieldValue, attributeName);
    }
    catch (final LDAPPersistException lpe)
    {
      Debug.debugException(lpe);
      throw lpe;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPPersistException(
           ERR_FIELD_INFO_CANNOT_ENCODE.get(field.getName(),
                containingClass.getName(), StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Sets the value of the associated field in the given object from the
   * information contained in the provided attribute.
   *
   * @param  o               The object for which to update the associated
   *                         field.
   * @param  e               The entry being decoded.
   * @param  failureReasons  A list to which information about any failures
   *                         may be appended.
   *
   * @return  {@code true} if the decode process was completely successful, or
   *          {@code false} if there were one or more failures.
   */
  boolean decode(@NotNull final Object o, @NotNull final Entry e,
                 @NotNull final List<String> failureReasons)
  {
    boolean successful = true;

    Attribute a = e.getAttribute(attributeName);
    if ((a == null) || (! a.hasValue()))
    {
      if (defaultDecodeValues.length > 0)
      {
        a = new Attribute(attributeName, defaultDecodeValues);
      }
      else
      {
        if (isRequiredForDecode)
        {
          successful = false;
          failureReasons.add(ERR_FIELD_INFO_MISSING_REQUIRED_ATTRIBUTE.get(
               containingClass.getName(), e.getDN(), attributeName,
               field.getName()));
        }

        try
        {
          encoder.setNull(field, o);
        }
        catch (final LDAPPersistException lpe)
        {
          Debug.debugException(lpe);
          successful = false;
          failureReasons.add(lpe.getMessage());
        }

        return successful;
      }
    }

    if (failOnTooManyValues && (a.size() > 1))
    {
      successful = false;
      failureReasons.add(ERR_FIELD_INFO_FIELD_NOT_MULTIVALUED.get(a.getName(),
           field.getName(), containingClass.getName()));
    }

    try
    {
      encoder.decodeField(field, o, a);
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
