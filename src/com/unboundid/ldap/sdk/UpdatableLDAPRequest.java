/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import java.util.List;

import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class is the superclass of all types of LDAP requests that can be
 * altered.  It provides methods for updating the set of controls to include as
 * part of the request and for configuring a response timeout, which is
 * the maximum length of time that the SDK should wait for a response to the
 * request before returning an error back to the caller.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public abstract class UpdatableLDAPRequest
       extends LDAPRequest
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2487230102594573848L;



  /**
   * Creates a new LDAP request with the provided set of controls.
   *
   * @param  controls  The set of controls to include in this LDAP request.
   */
  protected UpdatableLDAPRequest(@Nullable final Control[] controls)
  {
    super(controls);
  }



  /**
   * Specifies the set of controls for this request.
   *
   * @param  controls  The set of controls for this request.
   */
  public final void setControls(@Nullable final Control... controls)
  {
    if (controls == null)
    {
      setControlsInternal(NO_CONTROLS);
    }
    else
    {
      setControlsInternal(controls);
    }
  }



  /**
   * Specifies the set of controls for this request.
   *
   * @param  controls  The set of controls for this request.
   */
  public final void setControls(@Nullable final List<Control> controls)
  {
    if ((controls == null) || controls.isEmpty())
    {
      setControlsInternal(NO_CONTROLS);
    }
    else
    {
      final Control[] controlArray = new Control[controls.size()];
      setControlsInternal(controls.toArray(controlArray));
    }
  }



  /**
   * Removes all controls from this request.
   */
  public final void clearControls()
  {
    setControlsInternal(NO_CONTROLS);
  }



  /**
   * Adds the provided control to the set of controls for this request.
   *
   * @param  control  The control to add to the set of controls for this
   *                  request.  It must not be {@code null}.
   */
  public final void addControl(@NotNull final Control control)
  {
    Validator.ensureNotNull(control);

    final Control[] controls = getControls();

    final Control[] newControls = new Control[controls.length+1];
    System.arraycopy(controls, 0, newControls, 0, controls.length);
    newControls[controls.length] = control;

    setControlsInternal(newControls);
  }



  /**
   * Adds the provided controls to the set of controls for this request.
   *
   * @param  controls  The controls to add to the set of controls for this
   *                   request.
   */
  public final void addControls(@Nullable final Control... controls)
  {
    if ((controls == null) || (controls.length == 0))
    {
      return;
    }

    final Control[] currentControls = getControls();

    final Control[] newControls =
         new Control[currentControls.length + controls.length];
    System.arraycopy(currentControls, 0, newControls, 0,
                     currentControls.length);
    System.arraycopy(controls, 0, newControls, currentControls.length,
                     controls.length);

    setControlsInternal(newControls);
  }



  /**
   * Removes the control with the specified OID from the set of controls for
   * this request.  If this request has multiple controls with the same OID,
   * then only the first will be removed.
   *
   * @param  oid  The OID of the control to remove.  It must not be
   *              {@code null}.
   *
   * @return  The control that was removed, or {@code null} if this request does
   *          not have any control with the specified OID.
   */
  @Nullable()
  public final Control removeControl(@NotNull final String oid)
  {
    Validator.ensureNotNull(oid);

    final Control[] controls = getControls();

    int pos = -1;
    Control c = null;
    for (int i=0; i < controls.length; i++)
    {
      if (controls[i].getOID().equals(oid))
      {
        c = controls[i];
        pos = i;
        break;
      }
    }

    if (pos < 0)
    {
      return null;
    }

    if (controls.length == 1)
    {
      setControlsInternal(NO_CONTROLS);
    }
    else
    {
      final Control[] newControls = new Control[controls.length - 1];
      for (int i=0,j=0; i < controls.length; i++)
      {
        if (i != pos)
        {
          newControls[j++] = controls[i];
        }
      }
      setControlsInternal(newControls);
    }

    return c;
  }



  /**
   * Removes the provided control from the set of controls for this request.
   * This will have no impact if the provided control is not included in the set
   * of controls for this request.
   *
   * @param  control  The control to remove from the set of controls for this
   *                  request.  It must not be {@code null}.
   *
   * @return  {@code true} if the control was found and removed, or
   *          {@code false} if not.
   */
  public final boolean removeControl(@NotNull final Control control)
  {
    Validator.ensureNotNull(control);

    final Control[] controls = getControls();

    int pos = -1;
    for (int i=0; i < controls.length; i++)
    {
      if (controls[i].equals(control))
      {
        pos = i;
        break;
      }
    }

    if (pos < 0)
    {
      return false;
    }

    if (controls.length == 1)
    {
      setControlsInternal(NO_CONTROLS);
    }
    else
    {
      final Control[] newControls = new Control[controls.length - 1];
      for (int i=0,j=0; i < controls.length; i++)
      {
        if (i != pos)
        {
          newControls[j++] = controls[i];
        }
      }
      setControlsInternal(newControls);
    }

    return true;
  }



  /**
   * Replaces the control with the same OID as the provided control with the
   * provided control.  If no control with the same OID exists in the request,
   * then the control will be added to the request.  If the request has multiple
   * controls with the same OID as the new control, then only the first will be
   * replaced.
   *
   * @param  control  The control to use in place of the existing control with
   *                  the same OID.  It must not be {@code null}.
   *
   * @return  The control that was replaced, or {@code null} if there was no
   *          control with the same OID as the provided control.
   */
  @Nullable()
  public final Control replaceControl(@NotNull final Control control)
  {
    Validator.ensureNotNull(control);

    return replaceControl(control.getOID(), control);
  }



  /**
   * Replaces the control with the specified OID with the provided control. If
   * no control with the given OID exists in the request, then a new control
   * will be added.  If this request has multiple controls with the specified
   * OID, then only the first will be replaced.
   *
   * @param  oid      The OID of the control to replace with the provided
   *                  control.  It must not be {@code null}.
   * @param  control  The control to use in place of the control with the
   *                  specified OID.  It may be {@code null} if the control
   *                  should be removed.  It may have a different OID than the
   *                  OID of the control being replaced.
   *
   * @return  The control that was replaced, or {@code null} if there was no
   *          control with the specified OID.
   */
  @Nullable()
  public final Control replaceControl(@NotNull final String oid,
                                      @Nullable final Control control)
  {
    Validator.ensureNotNull(oid);

    if (control == null)
    {
      return removeControl(oid);
    }

    final Control[] controls = getControls();
    for (int i=0; i < controls.length; i++)
    {
      if (controls[i].getOID().equals(oid))
      {
        final Control c = controls[i];
        controls[i] = control;
        setControlsInternal(controls);
        return c;
      }
    }

    final Control[] newControls = new Control[controls.length+1];
    System.arraycopy(controls, 0, newControls, 0, controls.length);
    newControls[controls.length] = control;
    setControlsInternal(newControls);
    return null;
  }
}
