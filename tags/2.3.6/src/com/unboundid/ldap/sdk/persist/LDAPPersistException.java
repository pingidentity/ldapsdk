/*
 * Copyright 2009-2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2014 UnboundID Corp.
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



import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an exception that may be thrown if a problem occurs while
 * attempting to perform processing related to persisting Java objects in an
 * LDAP directory server.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPPersistException
       extends LDAPException
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8625904586803506713L;



  // The object that was in the process of being decoded, if available.  If it
  // is non-null, then it will likely only be partially initialized.
  private final Object partiallyDecodedObject;



  /**
   * Creates a new LDAP persist exception that wraps the provided LDAP
   * exception.
   *
   * @param  e  The LDAP exception to wrap with this LDAP persist exception.
   */
  public LDAPPersistException(final LDAPException e)
  {
    super(e);

    partiallyDecodedObject = null;
  }



  /**
   * Creates a new LDAP persist exception with the provided message.
   *
   * @param  message  The message for this exception.
   */
  public LDAPPersistException(final String message)
  {
    super(ResultCode.LOCAL_ERROR, message);

    partiallyDecodedObject = null;
  }



  /**
   * Creates a new LDAP persist exception with the provided message and cause.
   *
   * @param  message  The message for this exception.
   * @param  cause    The underlying cause for this exception.
   */
  public LDAPPersistException(final String message, final Throwable cause)
  {
    super(ResultCode.LOCAL_ERROR, message, cause);

    partiallyDecodedObject = null;
  }



  /**
   * Creates a new LDAP persist exception with the provided message and cause.
   *
   * @param  message                 The message for this exception.
   * @param  partiallyDecodedObject  The object that was in the process of being
   *                                 decoded when this exception was thrown.  It
   *                                 may be {@code null} if the exception was
   *                                 thrown outside of the context of decoding
   *                                 an object.  If an object is available, then
   *                                 it will likely be only partially
   *                                 initialized.
   * @param  cause                   The underlying cause for this exception.
   */
  public LDAPPersistException(final String message,
                              final Object partiallyDecodedObject,
                              final Throwable cause)
  {
    super(ResultCode.LOCAL_ERROR, message, cause);

    this.partiallyDecodedObject = partiallyDecodedObject;
  }



  /**
   * Retrieves the partially-decoded object in the process of being initialized
   * when this exception was thrown.
   *
   * @return  The partially-decoded object in the process of being initialized
   *          when this exception was thrown, or {@code null} if none is
   *          available or the exception was not thrown while decoding an
   *          object.
   */
  public Object getPartiallyDecodedObject()
  {
    return partiallyDecodedObject;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDAPPersistException(message='");
    buffer.append(getMessage());
    buffer.append('\'');

    if (partiallyDecodedObject != null)
    {
      buffer.append(", partiallyDecodedObject=");
      buffer.append(partiallyDecodedObject);
    }

    final Throwable cause = getCause();
    if (cause != null)
    {
      buffer.append(", cause=");
      buffer.append(StaticUtils.getExceptionMessage(cause));
    }

    buffer.append(')');
  }
}
