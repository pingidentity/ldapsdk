/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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
 * This annotation type may be used to mark a field whose value should be the
 * DN of the entry from which the corresponding object was initialized.  This
 * annotation type should only be used for at most one field in a given class,
 * and that class must be marked with the {@link LDAPObject} annotation type.
 * The field marked with this annotation type must have a type of
 * {@code java.lang.String}.
 */
@Documented()
@Retention(RetentionPolicy.RUNTIME)
@Target(value={ElementType.FIELD})
public @interface LDAPDNField
{
}
