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



import java.lang.annotation.ElementType;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.unboundid.util.NotNull;



/**
 * This annotation type may be used to mark fields whose values should be
 * persisted in an LDAP directory server.  It should only be used for fields in
 * classes that contain the {@link LDAPObject} annotation type.  Fields marked
 * with this annotation type must be non-final and non-static, but they may have
 * any access modifier (including {@code public}, {@code protected},
 * {@code private}, or no access modifier at all indicating package-level
 * access).  The associated attribute must not be referenced by any other
 * {@code LDAPField} annotation types.
 */
@Documented()
@Retention(RetentionPolicy.RUNTIME)
@Target(value={ElementType.FIELD})
public @interface LDAPField
{
  /**
   * Indicates whether attempts to initialize an object should fail if the LDAP
   * attribute has a value that cannot be stored in the associated field.  If
   * this is {@code true}, then an exception will be thrown in such instances.
   * If this is {@code false}, then the field will remain uninitialized, and
   * attempts to modify the corresponding entry in the directory may cause the
   * existing values to be lost.
   *
   * @return  {@code true} if attempts to initialize an object should fail if
   *          the LDAP attribute has a value that cannot be stored in the
   *          associated field, or {@code false} if not.
   */
  boolean failOnInvalidValue() default true;



  /**
   * Indicates whether attempts to initialize an object should fail if the
   * LDAP attribute has multiple values but the associated field can only hold a
   * single value.  If this is {@code true}, then an exception will be thrown in
   * such instances.  If this is {@code false}, then only the first value
   * returned will be used, and attempts to modify the corresponding entry in
   * the directory may cause those additional values to be lost.
   *
   * @return  {@code true} if attempts to initialize an object should fail if
   *          the LDAP attribute has multiple values but the associated field
   *          can only hold a single value, or {@code false} if not.
   */
  boolean failOnTooManyValues() default true;



  /**
   * Indicates whether this field should be included in the LDAP entry that is
   * generated when adding a new instance of the associated object to the
   * directory.  Note that any field which is to be included in entry RDNs will
   * always be included in add operations regardless of the value of this
   * element.
   *
   * @return  {@code true} if this field should be included in the LDAP entry
   *          that is generated when adding a new instance of the associated
   *          object to the directory, or {@code false} if not.
   */
  boolean inAdd() default true;



  /**
   * Indicates whether this field should be examined and included in the set of
   * LDAP modifications if it has been changed when modifying an existing
   * instance of the associated object in the directory.  Note that any field
   * which is to be included in entry RDNs will never be included in modify
   * operations regardless of the value of this element.
   *
   * @return  {@code true} if this field should be examined and included in the
   *          set of LDAP modifications if it has been changed, or {@code false}
   *          if not.
   */
  boolean inModify() default true;



  /**
   * Indicates whether the value of this field should be included in the RDN of
   * entries created from the associated object.  Any field which is to be
   * included entry RDNs will be considered required for add operations
   * regardless of the value of the {@link #requiredForEncode} element of this
   * annotation type, and will be included in add operations regardless of the
   * value of the {@link #inAdd} element.
   * <BR><BR>
   * When generating an entry DN, the persistence framework will construct an
   * RDN using all fields marked with {@code LDAPField} that have
   * {@code inRDN=true} and all getter methods marked with {@code LDAPGetter}
   * that have {@code inRDN=true}.  A class marked with {@code LDAPObject} must
   * either have at least one {@code LDAPField} or {@code LDAPGetter} with
   * {@code inRDN=true}, or it must be a direct subclass of another class marked
   * with {@code LDAPObject}.  If a class has one or more fields and/or getters
   * with {@code inRDN=true}, then only those fields/getters will be used to
   * construct the RDN, even if that class is a direct subclass of another class
   * marked with {@code LDAPObject}.
   *
   * @return  {@code true} if the value of this field should be included in the
   *          RDN of entries created from the associated object, or
   *          {@code false} if not.
   */
  boolean inRDN() default false;



  /**
   * Indicates whether this field should be lazily loaded, which means that the
   * associated attribute will not be retrieved by default so this field will
   * be uninitialized.  This may be useful for attributes which are not always
   * needed and that may be expensive to retrieve or could require a lot of
   * memory to hold.  The contents of such fields may be loaded on demand if
   * their values are needed.  Fields marked for lazy loading will never be
   * considered required for decoding, and they must not be given default values
   * or marked for inclusion in entry RDNs.
   *
   * @return  {@code true} if this field should be lazily loaded, or
   *          {@code false} if not.
   */
  boolean lazilyLoad() default false;



  /**
   * Indicates whether this field is required to be assigned a value in decode
   * processing.  If this is {@code true}, then attempts to initialize a Java
   * object from an LDAP entry which does not contain a value for the associated
   * attribute will result in an exception.
   *
   * @return  {@code true} if this field is required to be assigned a value in
   *          decode processing, or {@code false} if not.
   */
  boolean requiredForDecode() default false;



  /**
   * Indicates whether this field is required to have a value for encode
   * processing.  If this is {@code true}, then attempts to construct an entry
   * or set of modifications for an object that does not have a value for this
   * field will result in an exception.
   *
   * @return  {@code true} if this field is required to have a value for encode
   *          processing, or {@code false} if not.
   */
  boolean requiredForEncode() default false;



  /**
   * The class that provides the logic for encoding a field to an LDAP
   * attribute, and for initializing a field from an LDAP attribute.
   *
   * @return  The encoder class for the field.
   */
  @NotNull Class<? extends ObjectEncoder> encoderClass()
       default DefaultObjectEncoder.class;



  /**
   * Indicates whether and under what circumstances the value of this field may
   * be included in a search filter generated to search for entries that match
   * the object.
   *
   * @return  The filter usage value for this field.
   */
  @NotNull FilterUsage filterUsage() default FilterUsage.CONDITIONALLY_ALLOWED;



  /**
   * The name of the attribute type in which the associated field will be stored
   * in LDAP entries.  If no value is provided, then it will be assumed that the
   * LDAP attribute name matches the name of the associated field.
   *
   * @return  The name of the attribute type in which the associated field will
   *          be stored in LDAP entries, or an empty string if the attribute
   *          name should match the name of the associated field.
   */
  @NotNull String attribute() default "";



  /**
   * The string representations of the default values to assign to this
   * field if there are no values for the associated attribute in the
   * corresponding LDAP entry being used to initialize the object.  If no
   * default values are defined, then an exception will be thrown if the field
   * is {@link #requiredForEncode}, or the field will be set to {@code null} if
   * it is not required.
   *
   * @return  The string representations of the default values to assign to this
   *          field if there are no values for the associated attribute in the
   *          corresponding LDAP entry, or an empty array if there should not be
   *          any default values.
   */
  @NotNull String[] defaultDecodeValue() default {};



  /**
   * The string representations of the default values to use when adding an
   * entry to the directory if this field has a {@code null} value.
   *
   * @return  The string representations of the default values to use when
   *          adding an entry to the directory if this field has a {@code null}
   *          value, or an empty array if there should not be any default
   *          values.
   */
  @NotNull String[] defaultEncodeValue() default {};



  /**
   * The names of the object classes in which the associated attribute may be
   * used.  This is primarily intended for use in generating LDAP schema from
   * Java object types.
   * <BR><BR>
   * Values may include any combination of the structural and/or auxiliary
   * object classes named in the {@link LDAPObject} annotation type for the
   * associated class.  If no values are provided, then it will be assumed to
   * be only included in the structural object class.
   *
   * @return  The names of the object classes in which the associated attribute
   *          may be used, or an empty array if it should be assumed to only be
   *          included in the structural object class.
   */
  @NotNull String[] objectClass() default {};
}
