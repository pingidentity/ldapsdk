/*
 * Copyright 2011-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2018 Ping Identity Corporation
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



/**
 * This enum defines a set of filter types for filters that may be generated
 * for an object using the LDAP SDK persistence framework.  Classes created by
 * {@link GenerateSourceFromSchema} (including the
 * {@code generate-source-from-schema} command-line tool) will include methods
 * that may be used to generate filters for object contents.
 */
public enum PersistFilterType
{
  /**
   * The filter type that may be used to generate a presence filter, like
   * "(attrName=*)".
   */
  PRESENCE,



  /**
   * The filter type that may be used to generate an equality filter, like
   * "(attrName=value)".
   */
  EQUALITY,



  /**
   * The filter type that may be used to generate a substring filter with a
   * subInitial element, like "(attrName=value*)".
   */
  STARTS_WITH,



  /**
   * The filter type that may be used to generate a substring filter with a
   * subFinal element, like "(attrName=*value)".
   */
  ENDS_WITH,



  /**
   * The filter type that may be used to generate a substring filter with a
   * subAny element, like "(attrName=*value*)".
   */
  CONTAINS,



  /**
   * The filter type that may be used to generate a greater-than-or-equal-to
   * filter, like "(attrName&gt;=value)".
   */
  GREATER_OR_EQUAL,



  /**
   * The filter type that may be used to generate a less-than-or-equal-to
   * filter, like "(attrName&lt;=value)".
   */
  LESS_OR_EQUAL,



  /**
   * The filter type that may be used to generate an approximate match filter,
   * like "(attrName~=value)".
   */
  APPROXIMATELY_EQUAL_TO;
}
