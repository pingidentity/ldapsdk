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
package com.unboundid.ldap.sdk.controls;



import com.unboundid.ldap.sdk.Control;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a helper class that may be used to ensure that all of the
 * "out-of-the-box" response controls supported by this SDK are properly
 * registered so that they can be properly instantiated when received in a
 * response from the directory server.
 */
@InternalUseOnly()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
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
   * Registers all "out-of-the-box" response controls provided with this SDK so
   * that they may be properly decoded if they are received in an LDAP response.
   * This method is intended only for internal use only and should not be called
   * by external applications.
   */
  @InternalUseOnly()
  public static void registerDefaultResponseControls()
  {
    Control.registerDecodeableControl(
         AuthorizationIdentityResponseControl.
              AUTHORIZATION_IDENTITY_RESPONSE_OID,
         new AuthorizationIdentityResponseControl());

    Control.registerDecodeableControl(
         ContentSyncDoneControl.SYNC_DONE_OID,
         new ContentSyncDoneControl());

    Control.registerDecodeableControl(
         ContentSyncStateControl.SYNC_STATE_OID,
         new ContentSyncStateControl());

    Control.registerDecodeableControl(
         EntryChangeNotificationControl.ENTRY_CHANGE_NOTIFICATION_OID,
         new EntryChangeNotificationControl());

    Control.registerDecodeableControl(
         PostReadResponseControl.POST_READ_RESPONSE_OID,
         new PostReadResponseControl());

    Control.registerDecodeableControl(
         PreReadResponseControl.PRE_READ_RESPONSE_OID,
         new PreReadResponseControl());

    Control.registerDecodeableControl(
         ServerSideSortResponseControl.SERVER_SIDE_SORT_RESPONSE_OID,
         new ServerSideSortResponseControl());

    Control.registerDecodeableControl(
         SimplePagedResultsControl.PAGED_RESULTS_OID,
         new SimplePagedResultsControl());

    Control.registerDecodeableControl(
         PasswordExpiredControl.PASSWORD_EXPIRED_OID,
         new PasswordExpiredControl());

    Control.registerDecodeableControl(
         PasswordExpiringControl.PASSWORD_EXPIRING_OID,
         new PasswordExpiringControl());

    Control.registerDecodeableControl(
         VirtualListViewResponseControl.VIRTUAL_LIST_VIEW_RESPONSE_OID,
         new VirtualListViewResponseControl());
  }
}
