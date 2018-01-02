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
package com.unboundid.util;



import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;



/**
 * This annotation type is used to indicate that a non-final class or interface
 * is NOT intended to be extended or implemented by third-party code.  In order
 * to be completely safe, third-party code should only extend or implement code
 * marked with the {@code @Extensible} annotation type, but the
 * {@code @NotExtensible} annotation type can serve as a reminder for classes
 * or interfaces that are not intended to be extended or implemented by
 * third-party code.
 * <BR><BR>
 * This annotation type will appear in the generated Javadoc documentation for
 * classes and interfaces that include it.
 *
 * @see  Extensible
 */
@Documented()
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.TYPE })
public @interface NotExtensible
{
}
