/*
 * Copyright 2015-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
package com.unboundid.util.json;



import com.unboundid.util.LDAPSDKException;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an exception that can be thrown if a problem occurs while
 * performing JSON processing.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JSONException
       extends LDAPSDKException
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -769276547486681889L;



  /**
   * Creates a new JSON exception with the provided message.
   *
   * @param  message  A message explaining the problem that occurred.
   */
  public JSONException(final String message)
  {
    super(message);
  }



  /**
   * Creates a new JSON exception with the provided message and cause.
   *
   * @param  message  A message explaining the problem that occurred.
   * @param  cause    The underlying cause for this exception.
   */
  public JSONException(final String message, final Throwable cause)
  {
    super(message, cause);
  }
}
