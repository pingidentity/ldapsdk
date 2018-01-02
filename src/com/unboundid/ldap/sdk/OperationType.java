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
package com.unboundid.ldap.sdk;



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the set of LDAP operation types.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum OperationType
{
  /**
   * The operation type that will be used for abandon operations.
   */
  ABANDON,



  /**
   * The operation type that will be used for add operations.
   */
  ADD,



  /**
   * The operation type that will be used for bind operations.
   */
  BIND,



  /**
   * The operation type that will be used for compare operations.
   */
  COMPARE,



  /**
   * The operation type that will be used for delete operations.
   */
  DELETE,



  /**
   * The operation type that will be used for extended operations.
   */
  EXTENDED,



  /**
   * The operation type that will be used for modify operations.
   */
  MODIFY,



  /**
   * The operation type that will be used for modify DN operations.
   */
  MODIFY_DN,



  /**
   * The operation type that will be used for search operations.
   */
  SEARCH,



  /**
   * The operation type that will be used for unbind operations.
   */
  UNBIND;
}
