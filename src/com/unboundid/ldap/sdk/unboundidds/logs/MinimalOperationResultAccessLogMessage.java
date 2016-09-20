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

import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface defines a number of methods common to all types of operation
 * result access log messages.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface MinimalOperationResultAccessLogMessage
{
  /**
   * Retrieves the result code for the operation.
   *
   * @return  The result code for the operation, or {@code null} if it is not
   *          included in the log message.
   */
  ResultCode getResultCode();



  /**
   * Retrieves the diagnostic message for the operation.
   *
   * @return  The diagnostic message for the operation, or {@code null} if it is
   *          not included in the log message.
   */
  String getDiagnosticMessage();



  /**
   * Retrieves a message with additional information about the result of the
   * operation.
   *
   * @return  A message with additional information about the result of the
   *          operation, or {@code null} if it is not included in the log
   *          message.
   */
  String getAdditionalInformation();



  /**
   * Retrieves the matched DN for the operation.
   *
   * @return  The matched DN for the operation, or {@code null} if it is not
   *          included in the log message.
   */
  String getMatchedDN();



  /**
   * Retrieves the list of referral URLs for the operation.
   *
   * @return  The list of referral URLs for the operation, or an empty list if
   *          it is not included in the log message.
   */
  List<String> getReferralURLs();



  /**
   * Retrieves the length of time in milliseconds required to process the
   * operation.
   *
   * @return  The length of time in milliseconds required to process the
   *          operation, or {@code null} if it is not included in the log
   *          message.
   */
  Double getProcessingTimeMillis();



  /**
   * Retrieves the length of time in milliseconds the operation was required to
   * wait on the work queue.
   *
   * @return  The length of time in milliseconds the operation was required to
   *          wait on the work queue, or {@code null} if it is not included in
   *          the log message.
   */
  Double getQueueTimeMillis();
}
