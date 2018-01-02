/*
 * Copyright 2007-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.Extensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Validator.*;



/**
 * This class provides a framework that should be extended by all types of LDAP
 * requests.  It provides methods for interacting with the set of controls to
 * include as part of the request and configuring a response timeout, which is
 * the maximum length of time that the SDK should wait for a response to the
 * request before returning an error back to the caller.
 * <BR><BR>
 * {@code LDAPRequest} objects are not immutable and should not be considered
 * threadsafe.  A single {@code LDAPRequest} object instance should not be used
 * concurrently by multiple threads, but instead each thread wishing to process
 * a request should have its own instance of that request.  The
 * {@link #duplicate()} method may be used to create an exact copy of a request
 * suitable for processing by a separate thread.
 * <BR><BR>
 * Note that even though this class is marked with the @Extensible annotation
 * type, it should not be directly subclassed by third-party code.  Only the
 * {@link ExtendedRequest} and {@link SASLBindRequest} subclasses are actually
 * intended to be extended by third-party code.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public abstract class LDAPRequest
       implements ReadOnlyLDAPRequest
{
  /**
   * The set of controls that will be used if none were provided.
   */
  static final Control[] NO_CONTROLS = new Control[0];



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2040756188243320117L;



  // Indicates whether to automatically follow referrals returned while
  // processing this request.
  private Boolean followReferrals;

  // The set of controls for this request.
  private Control[] controls;

  // The intermediate response listener for this request.
  private IntermediateResponseListener intermediateResponseListener;

  // The maximum length of time in milliseconds to wait for the response from
  // the server.  The default value of -1 indicates that it should be inherited
  // from the associated connection.
  private long responseTimeout;



  /**
   * Creates a new LDAP request with the provided set of controls.
   *
   * @param  controls  The set of controls to include in this LDAP request.
   */
  protected LDAPRequest(final Control[] controls)
  {
    if (controls == null)
    {
      this.controls = NO_CONTROLS;
    }
    else
    {
      this.controls = controls;
    }

    followReferrals = null;
    responseTimeout = -1L;
    intermediateResponseListener = null;
  }



  /**
   * Retrieves the set of controls for this request.  The caller must not alter
   * this set of controls.
   *
   * @return  The set of controls for this request.
   */
  public final Control[] getControls()
  {
    return controls;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public final List<Control> getControlList()
  {
    return Collections.unmodifiableList(Arrays.asList(controls));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public final boolean hasControl()
  {
    return (controls.length > 0);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public final boolean hasControl(final String oid)
  {
    ensureNotNull(oid);

    for (final Control c : controls)
    {
      if (c.getOID().equals(oid))
      {
        return true;
      }
    }

    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public final Control getControl(final String oid)
  {
    ensureNotNull(oid);

    for (final Control c : controls)
    {
      if (c.getOID().equals(oid))
      {
        return c;
      }
    }

    return null;
  }



  /**
   * Updates the set of controls associated with this request.  This must only
   * be called by {@link UpdatableLDAPRequest}.
   *
   * @param  controls  The set of controls to use for this request.
   */
  final void setControlsInternal(final Control[] controls)
  {
    this.controls = controls;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public final long getResponseTimeoutMillis(final LDAPConnection connection)
  {
    if ((responseTimeout < 0L) && (connection != null))
    {
      return connection.getConnectionOptions().getResponseTimeoutMillis();
    }
    else
    {
      return responseTimeout;
    }
  }



  /**
   * Specifies the maximum length of time in milliseconds that processing on
   * this operation should be allowed to block while waiting for a response
   * from the server.  A value of zero indicates that no timeout should be
   * enforced.  A value that is less than zero indicates that the default
   * response timeout for the underlying connection should be used.
   *
   * @param  responseTimeout  The maximum length of time in milliseconds that
   *                          processing on this operation should be allowed to
   *                          block while waiting for a response from the
   *                          server.
   */
  public final void setResponseTimeoutMillis(final long responseTimeout)
  {
    if (responseTimeout < 0L)
    {
      this.responseTimeout = -1L;
    }
    else
    {
      this.responseTimeout = responseTimeout;
    }
  }



  /**
   * Indicates whether to automatically follow any referrals encountered while
   * processing this request.  If a value has been set for this request, then it
   * will be returned.  Otherwise, the default from the connection options for
   * the provided connection will be used.
   *
   * @param  connection  The connection whose connection options may be used in
   *                     the course of making the determination.  It must not
   *                     be {@code null}.
   *
   * @return  {@code true} if any referrals encountered during processing should
   *          be automatically followed, or {@code false} if not.
   */
  @Override()
  public final boolean followReferrals(final LDAPConnection connection)
  {
    if (followReferrals == null)
    {
      return connection.getConnectionOptions().followReferrals();
    }
    else
    {
      return followReferrals;
    }
  }



  /**
   * Indicates whether automatic referral following is enabled for this request.
   *
   * @return  {@code Boolean.TRUE} if automatic referral following is enabled
   *          for this request, {@code Boolean.FALSE} if not, or {@code null} if
   *          a per-request behavior is not specified.
   */
  final Boolean followReferralsInternal()
  {
    return followReferrals;
  }



  /**
   * Specifies whether to automatically follow any referrals encountered while
   * processing this request.  This may be used to override the default behavior
   * defined in the connection options for the connection used to process the
   * request.
   *
   * @param  followReferrals  Indicates whether to automatically follow any
   *                          referrals encountered while processing this
   *                          request.  It may be {@code null} to indicate that
   *                          the determination should be based on the
   *                          connection options for the connection used to
   *                          process the request.
   */
  public final void setFollowReferrals(final Boolean followReferrals)
  {
    this.followReferrals = followReferrals;
  }



  /**
   * Retrieves the intermediate response listener for this request, if any.
   *
   * @return  The intermediate response listener for this request, or
   *          {@code null} if there is none.
   */
  public final IntermediateResponseListener getIntermediateResponseListener()
  {
    return intermediateResponseListener;
  }



  /**
   * Sets the intermediate response listener for this request.
   *
   * @param  listener  The intermediate response listener for this request.  It
   *                   may be {@code null} to clear any existing listener.
   */
  public final void setIntermediateResponseListener(
                         final IntermediateResponseListener listener)
  {
    intermediateResponseListener = listener;
  }



  /**
   * Processes this operation using the provided connection and returns the
   * result.
   *
   * @param  connection  The connection to use to process the request.
   * @param  depth       The current referral depth for this request.  It should
   *                     always be one for the initial request, and should only
   *                     be incremented when following referrals.
   *
   * @return  The result of processing this operation.
   *
   * @throws  LDAPException  If a problem occurs while processing the request.
   */
  @InternalUseOnly()
  protected abstract LDAPResult process(LDAPConnection connection, int depth)
            throws LDAPException;



  /**
   * Retrieves the message ID for the last LDAP message sent using this request.
   *
   * @return  The message ID for the last LDAP message sent using this request,
   *          or -1 if it no LDAP messages have yet been sent using this
   *          request.
   */
  public abstract int getLastMessageID();



  /**
   * Retrieves the type of operation that is represented by this request.
   *
   * @return  The type of operation that is represented by this request.
   */
  public abstract OperationType getOperationType();



  /**
   * {@inheritDoc}
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public abstract void toString(StringBuilder buffer);
}
