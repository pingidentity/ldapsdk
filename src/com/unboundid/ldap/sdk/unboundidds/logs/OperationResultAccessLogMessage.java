/*
 * Copyright 2011-2016 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2016 UnboundID Corp.
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
package com.unboundid.ldap.sdk.unboundidds.logs;



import java.util.List;

import com.unboundid.util.NotExtensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 * This interface defines a number of methods common to all types of operation
 * result access log messages.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface OperationResultAccessLogMessage
       extends MinimalOperationResultAccessLogMessage
{
  /**
   * Retrieves the number of intermediate response messages returned in the
   * course of processing the operation.
   *
   * @return  The number of intermediate response messages returned to the
   *          client in the course of processing the operation, or {@code null}
   *          if it is not included in the log message.
   */
  Long getIntermediateResponsesReturned();



  /**
   * Retrieves the OIDs of any response controls contained in the log message.
   *
   * @return  The OIDs of any response controls contained in the log message, or
   *          an empty list if it is not included in the log message.
   */
  List<String> getResponseControlOIDs();



  /**
   * Retrieves a list of the additional servers that were accessed in the course
   * of processing the operation.  For example, if the access log message is
   * from a Directory Proxy Server instance, then this may contain a list of the
   * backend servers used to process the operation.
   *
   * @return  A list of the additional servers that were accessed in the course
   *          of processing the operation, or an empty list if it is not
   *          included in the log message.
   */
  List<String> getServersAccessed();



  /**
   * Retrieves the content of the intermediate client result for the
   * operation.
   *
   * @return  The content of the intermediate client result for the operation,
   *          or {@code null} if it is not included in the log message.
   */
  String getIntermediateClientResult();
}
