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
 * This annotation type may be used to mark methods whose return values should
 * be persisted in an LDAP directory server.  It should only be used for methods
 * in classes that contain the {@link LDAPObject} annotation type.  Those
 * methods must not be static and must have a non-{@code void} return type, but
 * they may have any access modifier (including {@code public},
 * {@code protected}, {@code private}, or no access modifier at all indicating
 * package-level access).  The associated attribute must not be referenced by
 * any other {@link LDAPField} or {@code LDAPGetter} annotations in the same
 * class, and it may be referenced by at most one {@link LDAPSetter} annotation.
 */
@Documented()
@Retention(RetentionPolicy.RUNTIME)
@Target(value={ElementType.METHOD})
public @interface LDAPGetter
{
  /**
   * Indicates whether the value returned from this method should be included in
   * the LDAP entry that is generated when adding a new instance of the
   * associated object to the directory.  Note that any getter value which is
   * to be included in entry RDNs will always be included in add operations
   * regardless of the value of this element.
   *
   * @return  {@code true} if the value returned from this method should be
   *          included in the LDAP entry that is generated when adding a new
   *          instance of the associated object to the directory, or
   *          {@code false} if not.
   */
  boolean inAdd() default true;



  /**
   * Indicates whether the value returned from this method should be included in
   * the set of LDAP modifications if it has been changed when modifying an
   * existing instance of the associated object in the directory.  Note that any
   * getter value which is to be included in entry RDNs will never be included
   * in modify operations regardless of the value of this element.
   *
   * @return  {@code true} if the value returned from this method should be
   *          included in the set of LDAP modifications if it has been changed
   *          when modifying an existing instance of the associated object in
   *          the directory, or {@code false} if not.
   */
  boolean inModify() default true;



  /**
   * Indicates whether the value returned from this method should be included in
   * the RDN of entries created from the associated object.  Any getter value
   * which is to be included entry RDNs will always be included in add
   * operations regardless of the value of the {@link #inAdd} element.
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
   * @return  {@code true} if the value returned from this method should be
   *          included in the RDN of entries created from the associated
   *          object, or {@code false} if not.
   */
  boolean inRDN() default false;



  /**
   * The class that provides the logic for encoding the method return value to
   * an LDAP attribute.
   *
   * @return  The encoder class for this getter.
   */
  @NotNull Class<? extends ObjectEncoder> encoderClass()
       default DefaultObjectEncoder.class;



  /**
   * Indicates whether and under what circumstances the value returned from this
   * method may be included in a search filter generated to search for entries
   * that match the object.
   *
   * @return  The filter usage value for this getter.
   */
  @NotNull FilterUsage filterUsage() default FilterUsage.CONDITIONALLY_ALLOWED;



  /**
   * The name of the attribute type in which the associated getter value will be
   * stored in LDAP entries.  If this is not provided, then the method name must
   * start with "get" and it will be assumed that the attribute name is the
   * remainder of the method name.
   *
   * @return  The name of the attribute type in which the associated getter
   *          value will be stored in LDAP entries, or an empty string if it
   *          will be assumed that the attribute name matches the getter method
   *          name without the initial "get".
   */
  @NotNull String attribute() default "";



  /**
   * The names of the object classes in which the associated attribute may
   * be used.  This is primarily intended for use in generating LDAP schema from
   * Java object types.
   * <BR><BR>
   * Values may include any combination of the structural and/or auxiliary
   * object classes named in the {@link LDAPObject} annotation type for the
   * associated class.  If no values are provided, then it will be assumed to
   * be only included in the structural object class.
   *
   * @return  The names of the object classes in which the associated attribute
   *          may be used, or an empty array if it will be assumed to only be
   *          included in the structural object class.
   */
  @NotNull String[] objectClass() default {};
}
