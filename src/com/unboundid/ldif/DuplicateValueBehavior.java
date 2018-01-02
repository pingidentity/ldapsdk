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
 * LDIF reader when encountering entries with duplicate attribute values.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum DuplicateValueBehavior
{
  /**
   * Indicates that duplicate values should be stripped, so that the resulting
   * entry will have only one copy of the value.
   */
  STRIP,



  /**
   * Indicates that duplicate values should be retained, so that the resulting
   * entry may have multiple copies of the value.  This is illegal and may cause
   * significant problems with attempts to use the resulting entry.
   */
  RETAIN,



  /**
   * Indicates that any entry containing duplicate attribute values should be
   * rejected.
   */
  REJECT;
}
