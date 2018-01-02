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
package com.unboundid.util.args;



import com.unboundid.util.LDAPSDKException;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an exception that may be thrown if a problem occurs while
 * parsing command line arguments or preparing the argument parser.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ArgumentException
       extends LDAPSDKException
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8353938257797371099L;



  /**
   * Creates a new argument exception with the provided message.
   *
   * @param  message  The message to use for this exception.
   */
  public ArgumentException(final String message)
  {
    super(message);
  }


  /**
   * Creates a new argument exception with the provided message and cause.
   *
   * @param  message  The message to use for this exception.
   * @param  cause    The underlying exception that triggered this exception.
   */
  public ArgumentException(final String message, final Throwable cause)
  {
    super(message, cause);
  }
}
