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
 * This annotation type may be used to mark classes for objects that may be
 * persisted in an LDAP directory server.  It may only be used to mark classes,
 * and should not be used for interfaces or annotation types.  Classes with this
 * annotation type must provide a default zero-argument constructor.  Fields in
 * the associated class which are to be persisted should be marked with the
 * {@link LDAPField} annotation type.
 */
@Documented()
@Retention(RetentionPolicy.RUNTIME)
@Target(value={ElementType.TYPE})
public @interface LDAPObject
{
  /**
   * Indicates whether to request all attributes when performing searches to
   * retrieve objects of this type.  If this is {@code true}, then the search
   * request will attempt to retrieve all user and operational attributes.  If
   * this is {@code false}, then the search request will attempt to retrieve
   * only those attributes which are referenced by an {@link LDAPField} or
   * {@link LDAPSetter} annotation.  Note that if this is given a value of
   * {@code true}, then lazy loading will be disabled.
   *
   * @return  {@code true} if all attributes should be requested, or
   *          {@code false} if only referenced attributes should be requested.
   */
  boolean requestAllAttributes() default false;



  /**
   * The DN of the entry below which objects of this type will be created if no
   * alternate parent DN is specified.  A value equal to the empty string
   * indicates that there should be no default parent DN.
   * <BR><BR>
   * If a class marked with the {@code LDAPObject} annotation type does not
   * specify a default parent DN but is a direct subclass of another class
   * marked with {@code LDAPObject}, then the subclass will inherit the default
   * parent DN from the superclass.
   *
   * @return  The DN of the entry below which objects of this type will be
   *          created if no alternate parent DN is specified, or the empty
   *          string if there should be no default parent DN.
   */
  @NotNull String defaultParentDN() default "";



  /**
   * The name of a method that should be invoked on an object after all other
   * decode processing has been performed for that object.  It may perform any
   * additional work or validation that is not available as part of the LDAP SDK
   * persistence framework.  If a method name is provided, then that method must
   * exist in the associated class and it must not take any arguments.  It may
   * throw any kind of exception if the object is not valid.
   *
   * @return  The name of a method that should be invoked on an object after all
   *          other decode processing has been performed for that object, or an
   *          empty string if no post-decode method has been defined.
   */
  @NotNull String postDecodeMethod() default "";



  /**
   * The name of a method that should be invoked after an object has been
   * encoded to an LDAP entry.  It may alter the generated entry in any way,
   * including adding, removing, or replacing attributes, or altering the entry
   * DN.  If a method name is provided, then that method must exist in the
   * associated class and it must take exactly one argument, with a type of
   * {@link com.unboundid.ldap.sdk.Entry}.  It may throw any kind of exception
   * if a problem is found with the entry and it should not be used.
   *
   * @return  The name of a method that should be invoked after an object has
   *          been encoded to an LDAP entry, or an empty string if no
   *          post-encode method has been defined.
   */
  @NotNull String postEncodeMethod() default "";



  /**
   * The name of the structural object class for LDAP entries created from the
   * associated object type.  If no value is provided, then it will be assumed
   * that the object class name is equal to the unqualified name of the Java
   * class.
   *
   * @return  The name of the structural object class for LDAP entries created
   *          from the associated object type, or an empty string if the object
   *          class name will be assumed to be equal to the unqualified name of
   *          the Java class.
   */
  @NotNull String structuralClass() default "";



  /**
   * The name) of any auxiliary object classes for LDAP entries created from the
   * associated object type.
   *
   * @return  The names of any auxiliary object classes for LDAP entries created
   *          from the associated object type, or an empty array if entries
   *          should not include any auxiliary object classes.
   */
  @NotNull String[] auxiliaryClass() default {};



  /**
   * The names of any superior object classes for the structural and auxiliary
   * object classes that should be included in generated entries.
   *
   * @return  The names of any superior object classes for the structural and
   *          auxiliary object classes that should be included in generated
   *          entries, or an empty array if no superior classes should be
   *          included.
   */
  @NotNull String[] superiorClass() default {};
}
