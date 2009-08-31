/*
 * Copyright 2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009 UnboundID Corp.
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
package com.unboundid.android.ldap.browser;



import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.view.View;
import android.view.View.OnClickListener;



/**
 * This class provides an on-click listener that is meant to display a map of
 * the specified address when the associated view is clicked.
 */
class MapOnClickListener
      implements OnClickListener
{
  // The activity that created this on-click listener.
  private final Activity activity;

  // The address to map.
  private final String address;



  /**
   * Creates a new map on-click listener that will display a map of the
   * specified address when the associated view is clicked.
   *
   * @param  activity  The activity that created this on-click listener.
   * @param  address   The address to map.
   */
  public MapOnClickListener(final Activity activity, final String address)
  {
    this.activity = activity;
    this.address  = address;
  }



  /**
   * Indicates that the associated view was clicked and that a map of the
   * specified location should be displayed.
   *
   * @param  view  The view that was clicked.
   */
  public void onClick(final View view)
  {
    Intent i = new Intent(Intent.ACTION_VIEW,
                          Uri.parse("geo:0,0?q=" + address));
    activity.startActivity(i);
  }
}
