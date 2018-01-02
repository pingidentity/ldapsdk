/*
 * Copyright 2017-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2018 Ping Identity Corporation
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
package com.unboundid.util.ssl.cert;



import com.unboundid.util.LDAPSDKException;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an exception that can be thrown if a problem is
 * encountered while performing certificate processing.
 */
@NotMutable()
@ThreadSafety(level= ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CertException
       extends LDAPSDKException
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4999182955315408793L;



  /**
   * Creates a new certificate exception with the provided message.
   *
   * @param  message  The message to use for this exception.
   */
  public CertException(final String message)
  {
    super(message);
  }



  /**
   * Creates a new certificate exception with the provided message.
   *
   * @param  message  The message to use for this exception.
   * @param  cause    The exception that triggered this exception.
   */
  public CertException(final String message, final Throwable cause)
  {
    super(message, cause);
  }
}
