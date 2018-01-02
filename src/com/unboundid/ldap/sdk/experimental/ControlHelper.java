/*
 * Copyright 2007-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2007-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.experimental;



import com.unboundid.ldap.sdk.Control;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a helper class that may be used to ensure that all of the
 * "out-of-the-box" experimental response controls supported by this SDK
 * are registered so that they can be properly instantiated when received in a
 * response from the directory server.
 */
@InternalUseOnly()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ControlHelper
{
  /**
   * Prevent this class from being instantiated.
   */
  private ControlHelper()
  {
    // No implementation is required.
  }



  /**
   * Registers all "out-of-the-box" response UnboundID-specific controls
   * provided with this SDK so that they may be properly decoded if they are
   * received in an LDAP response.  This method is intended only for internal
   * use only and should not be called by external applications.
   */
  @InternalUseOnly()
  public static void registerDefaultResponseControls()
  {
    Control.registerDecodeableControl(
         ActiveDirectoryDirSyncControl.DIRSYNC_OID,
         new ActiveDirectoryDirSyncControl());
  }



  /**
   * Registers all "out-of-the-box" response UnboundID-specific controls
   * provided with this SDK so that they may be properly decoded if they are
   * received in an LDAP response.  This method is intended only for internal
   * use only and should not be called by external applications.
   */
  @InternalUseOnly()
  public static void registerNonCommercialResponseControls()
  {
    Control.registerDecodeableControl(
         DraftBeheraLDAPPasswordPolicy10ResponseControl.
              PASSWORD_POLICY_RESPONSE_OID,
         new DraftBeheraLDAPPasswordPolicy10ResponseControl());
  }
}
