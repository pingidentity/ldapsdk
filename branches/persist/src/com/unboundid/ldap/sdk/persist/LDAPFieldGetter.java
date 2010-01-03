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



import java.lang.annotation.ElementType;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;



/**
 * This annotation type may be used to mark methods whose return values should
 * be persisted in an LDAP directory server.  It should only be used for methods
 * in classes that contain the {@link LDAPObject} annotation type.  Those
 * methods must not be static and must have a non-{@code void} return type, but
 * they may have any access modifier (including {@code public},
 * {@code protected}, {@code private}, or no access modifier at all indicating
 * package-level access).  The associated attribute must not be referenced by
 * any other {@link LDAPField} or {@code LDAPFieldGetter} annotations in the
 * same class, and it may be referenced by at most one {@link LDAPFieldSetter}
 * annotation.
 */
@Documented()
@Retention(RetentionPolicy.RUNTIME)
@Target(value={ElementType.METHOD})
public @interface LDAPFieldGetter
{
  /**
   * Indicates whether the value returned from this method should be included in
   * the LDAP entry that is generated when adding a new instance of the
   * associated object to the directory.  Note that any field which is to be
   * included in entry RDNs will always be included in add operations regardless
   * of the value of this element.
   */
  boolean inAdd() default true;



  /**
   * Indicates whether the value returned from this method should be included in
   * the set of LDAP modifications if it has been changed when modifying an
   * existing instance of the associated object in the directory.  Note that any
   * field which is to be included in entry RDNs will never be included in
   * modify operations regardless of the value of this element.
   */
  boolean inModify() default true;



  /**
   * Indicates whether the value returned from this method should be included in
   * the RDN of entries created from the associated object.  Any field which is
   * to be included entry RDNs will always be included in add operations
   * regardless of the value of the {@link #inAdd} element.
   */
  boolean inRDN() default false;



  /**
   * The class that provides the logic for encoding a field to an LDAP
   * attribute, and for initializing a field from an LDAP attribute.
   */
  Class<? extends LDAPFieldEncoder> encoderClass()
       default DefaultLDAPFieldEncoder.class;



  /**
   * Indicates whether and under what circumstances the value returned from this
   * method may be included in a search filter generated to search for entries
   * that match the object.
   */
  FilterUsage filterUsage() default FilterUsage.CONDITIONALLY_ALLOWED;



  /**
   * The name of the attribute type in which the associated field will be stored
   * in LDAP entries.
   */
  String attribute();



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
