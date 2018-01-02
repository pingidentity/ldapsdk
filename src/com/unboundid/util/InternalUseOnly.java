/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
 * This annotation type, may be used to mark a class, constructor, or method
 * that is part of the LDAP SDK codebase to be for internal use only, and
 * therefore something that should not be accessed by third-party code.  If a
 * class is marked with the {@code @InternalUseOnly} annotation, then no part of
 * that class should be used by third-party code.  If a class is not marked with
 * the {@code @InternalUseOnly} annotation, then it may be assumed that the
 * class is part of the public API, and any public constructors and methods
 * which do not have the {@code @InternalUseOnly} annotation may be used by
 * third-party code.
 */
@Documented()
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.TYPE, ElementType.CONSTRUCTOR, ElementType.METHOD,
          ElementType.PACKAGE })
public @interface InternalUseOnly
{
}
