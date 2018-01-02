/*
 * Copyright 2012-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2012-2018 Ping Identity Corporation
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
package com.unboundid.ldif;



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines a set of possible behaviors that may be exhibited by the
 * LDIF reader when encountering trailing spaces in attribute values that are
 * not base64-encoded.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum TrailingSpaceBehavior
{
  /**
   * Indicates that illegal trailing spaces should be silently stripped from
   * attribute values.
   */
  STRIP,



  /**
   * Indicates that illegal trailing spaces should be retained (as if the value
   * had been base64-encoded).
   */
  RETAIN,



  /**
   * Indicates that illegal trailing spaces should cause the associated entry to
   * be rejected.
   */
  REJECT;
}
