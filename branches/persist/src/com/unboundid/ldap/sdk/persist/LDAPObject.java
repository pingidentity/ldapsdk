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
   * The name of the structural object class for LDAP entries created from the
   * associated object type.  If no value is provided, then it will be assumed
   * that the object class name is equal to the unqualified name of the Java
   * class.
   */
  String structuralClass() default "";



  /**
   * The name(s) of any auxiliary object class(es) for LDAP entries created from
   * the associated object type.
   */
  String[] auxiliaryClass() default {};
}
