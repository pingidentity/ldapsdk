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



import java.lang.annotation.ElementType;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;



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
   */
  boolean failOnInvalidValue() default true;



  /**
   * Indicates whether attempts to initialize an object should fail if the
   * LDAP attribute has multiple values but the associated field can only hold a
   * single value.  If this is {@code true}, then an exception will be thrown in
   * such instances.  If this is {@code false}, then only the first value
   * returned will be used, and attempts to modify the corresponding entry in
   * the directory may cause those additional values to be lost.
   */
  boolean failOnTooManyValues() default true;



  /**
   * Indicates whether this field should be included in the LDAP entry that is
   * generated when adding a new instance of the associated object to the
   * directory.
   */
  boolean inAdd() default true;



  /**
   * Indicates whether this field should be included in the filter that is
   * generated when searching for entries representing the associated object
   * type in the directory.
   */
  boolean inFilter() default false;



  /**
   * Indicates whether this field should be examined and included in the set of
   * LDAP modifications if it has been changed when modifying an existing
   * instance of the associated object in the directory.
   */
  boolean inModify() default true;



  /**
   * Indicates whether the value of this field should be included in the RDN of
   * entries created from the associated object.  Any field which is to be
   * included entry RDNs will be considered required for add operations
   * regardless of the value of the {@link #required} element of this annotation
   * type, and will be included in add operations regardless of the value of the
   * {@link #inAdd} element.
   */
  boolean inRDN() default false;



  /**
   * Indicates whether this field is required to have a value.  Attempts to
   * create an LDAP entry from an object without a value set for this field will
   * result in an exception.  Attempts to initialize a Java object from an LDAP
   * entry which does not contain a value for the associated attribute type and
   * no value(s) returned by the {@link #defaultReadValue} element of this
   * annotation type will also result in an exception.
   */
  boolean required() default false;



  /**
   * The class that provides the logic for encoding a field to an LDAP
   * attribute, and for initializing a field from an LDAP attribute.
   */
  Class<? extends LDAPFieldEncoder> encoderClass()
       default DefaultLDAPFieldEncoder.class;



  /**
   * The name of the attribute type in which the associated field will be stored
   * in LDAP entries.  If no value is provided, then it will be assumed that the
   * LDAP attribute name matches the name of the associated field.
   */
  String attribute() default "";



  /**
   * The string representation(s) of the default value to use when adding an
   * entry to the directory if this field has a {@code null} value.
   */
  String[] defaultAddValue() default {};



  /**
   * The string representation(s) of the default value(s) to assign to this
   * field if there are no values for the associated attribute in the
   * corresponding LDAP entry being used to initialize the object.  If no
   * default values are defined, then an exception will be thrown if the field
   * is {@link #required}, or the field will be set to {@code null} if it is
   * not required.
   */
  String[] defaultReadValue() default {};



  /**
   * The name(s) of the object class(es) in which the associated attribute may
   * be used.  This is primarily intended for use in generating LDAP schema from
   * Java object types.
   * <BR><BR>
   * Values may include any combination of the structural and/or auxiliary
   * object classes named in the {@link LDAPObject} annotation type for the
   * associated class.  If no values are provided, then it will be assumed to
   * be only included in the structural object class.
   */
  String[] objectClass() default {};
}
