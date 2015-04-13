/*
 * Copyright 2012-2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2012-2014 UnboundID Corp.
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



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an exception that can be thrown if the server sends a bind
 * response with a result code of {@link ResultCode#SASL_BIND_IN_PROGRESS},
 * which indicates that SASL bind processing has not yet completed.  This is not
 * an error, but neither does it indicate that bind processing has completed.
 * This exception provides access to the bind result and the server SASL
 * credentials that it may optionally contain so that this information may be
 * used to continue bind processing.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SASLBindInProgressException
       extends LDAPException
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2842513438320459264L;



  // The bind result for this exception.
  private final BindResult bindResult;



  /**
   * Creates a new SASL bind in progress exception from the provided bind
   * result.
   *
   * @param  bindResult  The bind result to use to create this exception.
   */
  SASLBindInProgressException(final BindResult bindResult)
  {
    super(bindResult);

    this.bindResult = bindResult;
  }



  /**
   * Retrieves the bind result that was returned by the server.
   *
   * @return  The bind result that was returned by the server.
   */
  public BindResult getBindResult()
  {
    return bindResult;
  }



  /**
   * Retrieves the server SASL credentials included in the bind result, if any.
   *
   * @return  The server SASL credentials included in the bind result, or
   *          {@code null} if the bind result did not include any server SASL
   *          credentials.
   */
  public ASN1OctetString getServerSASLCredentials()
  {
    return bindResult.getServerSASLCredentials();
  }
}
