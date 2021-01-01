/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import java.io.Serializable;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure which may be used to define a set of
 * constraints that may be used when processing operations.
 * <BR><BR>
 * This class is primarily intended to be used in the process of updating
 * applications which use the Netscape Directory SDK for Java to switch to or
 * coexist with the UnboundID LDAP SDK for Java.  For applications not written
 * using the Netscape Directory SDK for Java, the
 * {@link com.unboundid.ldap.sdk.LDAPConnectionOptions} class should be used
 * instead.
 */
@NotExtensible()
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public class LDAPConstraints
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6843729471197926148L;



  // Indicates whether to follow referrals.
  private boolean followReferrals;

  // The referral hop limit.
  private int hopLimit;

  // The response time limit in milliseconds.
  private int timeLimit;

  // The mechanism to use to authenticate to the target server when following
  // referrals.
  @Nullable private LDAPBind bindProc;

  // The client controls.
  @NotNull private LDAPControl[] clientControls;

  // The server controls.
  @NotNull private LDAPControl[] serverControls;

  // The mechanism to use to obtain credentials used when authenticating a
  // referral connection.
  @Nullable private LDAPRebind rebindProc;



  /**
   * Creates a new default set of constraints.
   */
  public LDAPConstraints()
  {
    bindProc        = null;
    clientControls  = new LDAPControl[0];
    followReferrals = false;
    hopLimit        = 5;
    rebindProc      = null;
    serverControls  = new LDAPControl[0];
    timeLimit       = 0;
  }



  /**
   * Creates a set of LDAP constraints with the provided information.
   *
   * @param  msLimit      The maximum length of time in milliseconds to wait for
   *                      a response from the server.
   * @param  doReferrals  Indicates whether to attempt to follow referrals.
   * @param  bindProc     The object to use to authenticate a connection when
   *                      following referrals.
   * @param  hopLimit     The maximum number of hops to take when following a
   *                      referral.
   */
  public LDAPConstraints(final int msLimit, final boolean doReferrals,
                         @Nullable final LDAPBind bindProc, final int hopLimit)
  {
    this();

    timeLimit       = msLimit;
    followReferrals = doReferrals;
    this.bindProc   = bindProc;
    this.hopLimit   = hopLimit;
  }



  /**
   * Creates a set of LDAP constraints with the provided information.
   *
   * @param  msLimit      The maximum length of time in milliseconds to wait for
   *                      a response from the server.
   * @param  doReferrals  Indicates whether to attempt to follow referrals.
   * @param  rebindProc   The object to use to provide the information needed to
   *                      authenticate a connection created for following a
   *                      referral.
   * @param  hopLimit     The maximum number of hops to take when following a
   *                      referral.
   */
  public LDAPConstraints(final int msLimit, final boolean doReferrals,
                         @Nullable final LDAPRebind rebindProc,
                         final int hopLimit)
  {
    this();

    timeLimit       = msLimit;
    followReferrals = doReferrals;
    this.rebindProc = rebindProc;
    this.hopLimit   = hopLimit;
  }



  /**
   * Retrieves the maximum length of time in milliseconds to wait for a response
   * from the server.
   *
   * @return  The maximum length of time in milliseconds to wait for a response
   *          from the server.
   */
  public int getTimeLimit()
  {
    return timeLimit;
  }



  /**
   * Specifies the maximum length of time in milliseconds to wait for a response
   * from the server.
   *
   * @param  timeLimit  The maximum length of time in milliseconds to wait for a
   *                    response from the server.
   */
  public void setTimeLimit(final int timeLimit)
  {
    if (timeLimit < 0)
    {
      this.timeLimit = 0;
    }
    else
    {
      this.timeLimit = timeLimit;
    }
  }



  /**
   * Indicates whether the client should automatically attempt to follow
   * referrals.
   *
   * @return  {@code true} if the client should attempt to follow referrals, or
   *          {@code false} if not.
   */
  public boolean getReferrals()
  {
    return followReferrals;
  }



  /**
   * Specifies whether the client should automatically attempt to follow
   * referrals.
   *
   * @param  doReferrals  Indicates whether the client should automatically
   *                      attempt to follow referrals.
   */
  public void setReferrals(final boolean doReferrals)
  {
    followReferrals = doReferrals;
  }



  /**
   * Retrieves the object that should be used to authenticate connections when
   * following referrals.
   *
   * @return  The object that should be used to authenticate connections when
   *          following referrals, or {@code null} if none has been defined.
   */
  @Nullable()
  public LDAPBind getBindProc()
  {
    return bindProc;
  }



  /**
   * Specifies the object that should be used to authenticate connections when
   * following referrals.
   *
   * @param  bindProc  The object that should be used to authenticate
   *                   connections when following referrals.
   */
  public void setBindProc(@Nullable final LDAPBind bindProc)
  {
    this.bindProc = bindProc;
  }



  /**
   * Retrieves the object that should be used to obtain authentication
   * information for use when following referrals.
   *
   * @return  The object that should be used to obtain authentication
   *          information for use when following referrals, or {@code null} if
   *          none has been defined.
   */
  @Nullable()
  public LDAPRebind getRebindProc()
  {
    return rebindProc;
  }



  /**
   * Specifies the object that should be used to obtain authentication
   * information for use when following referrals.
   *
   * @param  rebindProc  The object that should be used to obtain authentication
   *                     information for use when following referrals.
   */
  public void setRebindProc(@Nullable final LDAPRebind rebindProc)
  {
    this.rebindProc = rebindProc;
  }



  /**
   * Retrieves the maximum number of hops to take when attempting to follow a
   * referral.
   *
   * @return  The maximum number of hops to take when attempting to follow a
   *          referral.
   */
  public int getHopLimit()
  {
    return hopLimit;
  }



  /**
   * Retrieves the maximum number of hops to take when attempting to follow a
   * referral.
   *
   * @param  hopLimit  The maximum number of hops to take when attempting to
   *                   follow a referral.
   */
  public void setHopLimit(final int hopLimit)
  {
    if (hopLimit < 0)
    {
      this.hopLimit = 0;
    }
    else
    {
      this.hopLimit = hopLimit;
    }
  }



  /**
   * Retrieves the controls that should be applied by the clients.
   *
   * @return The controls that should be applied by the client.
   */
  @NotNull()
  public LDAPControl[] getClientControls()
  {
    return clientControls;
  }



  /**
   * Specifies the controls that should be applied by the client.
   *
   * @param  control  The control that should be applied by client.
   */
  public void setClientControls(@NotNull final LDAPControl control)
  {
    clientControls = new LDAPControl[] { control };
  }



  /**
   * Specifies the controls that should be applied by the client.
   *
   * @param  controls  The controls that should be applied by client.
   */
  public void setClientControls(@Nullable final LDAPControl[] controls)
  {
    if (controls == null)
    {
      clientControls = new LDAPControl[0];
    }
    else
    {
      clientControls = controls;
    }
  }



  /**
   * Retrieves the controls that should be applied by the server.
   *
   * @return The controls that should be applied by the server.
   */
  @NotNull()
  public LDAPControl[] getServerControls()
  {
    return serverControls;
  }



  /**
   * Specifies the controls that should be applied by the server.
   *
   * @param  control  The control that should be applied by server.
   */
  public void setServerControls(@NotNull final LDAPControl control)
  {
    serverControls = new LDAPControl[] { control };
  }



  /**
   * Specifies the controls that should be applied by the server.
   *
   * @param  controls  The controls that should be applied by server.
   */
  public void setServerControls(@Nullable final LDAPControl[] controls)
  {
    if (controls == null)
    {
      serverControls = new LDAPControl[0];
    }
    else
    {
      serverControls = controls;
    }
  }



  /**
   * Retrieves a duplicate of this LDAP constraints object.
   *
   * @return  A duplicate of this LDAP constraints object.
   */
  @NotNull()
  public LDAPConstraints duplicate()
  {
    final LDAPConstraints c = new LDAPConstraints();

    c.bindProc        = bindProc;
    c.clientControls  = clientControls;
    c.followReferrals = followReferrals;
    c.hopLimit        = hopLimit;
    c.rebindProc      = rebindProc;
    c.serverControls  = serverControls;
    c.timeLimit       = timeLimit;

    return c;
  }



  /**
   * Retrieves a string representation of this LDAP constraints object.
   *
   * @return  A string representation of this LDAP constraints object.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();

    buffer.append("LDAPConstraints(followReferrals=");
    buffer.append(followReferrals);
    buffer.append(", bindProc=");
    buffer.append(String.valueOf(bindProc));
    buffer.append(", rebindProc=");
    buffer.append(String.valueOf(rebindProc));
    buffer.append(", hopLimit=");
    buffer.append(hopLimit);
    buffer.append(", timeLimit=");
    buffer.append(timeLimit);
    buffer.append(", clientControls={");

    for (int i=0; i < clientControls.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      buffer.append(clientControls[i].toString());
    }

    buffer.append("}, serverControls={");

    for (int i=0; i < serverControls.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      buffer.append(serverControls[i].toString());
    }

    buffer.append("})");

    return buffer.toString();
  }
}
