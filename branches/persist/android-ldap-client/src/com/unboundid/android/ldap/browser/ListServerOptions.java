/*
 * Copyright 2009-2010 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2010 UnboundID Corp.
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



import java.util.LinkedHashMap;
import java.util.Map;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ArrayAdapter;
import android.widget.ListView;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides an Android activity that may be used to display a set
 * of options to perform on a server instance.
 */
public class ListServerOptions
       extends Activity
       implements OnItemClickListener
{
  /**
   * The name of the field used to provide the server instance.
   */
  public static final String BUNDLE_FIELD_INSTANCE = "SERVER_OPTIONS_INSTANCE";



  // The instance that was selected.
  private ServerInstance instance;



  /**
   * Performs all necessary processing when this activity is started or resumed.
   */
  @Override()
  protected void onResume()
  {
    super.onResume();

    setContentView(R.layout.listserveroptions);


    // Get the instance on which to operate.
    Intent intent = getIntent();
    Bundle extras = intent.getExtras();

    instance = (ServerInstance) extras.getSerializable(BUNDLE_FIELD_INSTANCE);


    // Populate the list of options.
    String[] options =
    {
      "Search this server",
      "Edit settings for server",
      "Remove this server"
    };

    ListView optionList = (ListView) findViewById(R.id.list_server_options);
    ArrayAdapter<String> listAdapter = new ArrayAdapter<String>(this,
         android.R.layout.simple_list_item_1, options);
    optionList.setAdapter(listAdapter);
    optionList.setOnItemClickListener(this);
  }



  /**
   * Takes any appropriate action after a list item was clicked.
   *
   * @param  parent    The list containing the item that was clicked.
   * @param  item      The item that was clicked.
   * @param  position  The position of the item that was clicked.
   * @param  id        The ID of the item that was clicked.
   */
  public void onItemClick(final AdapterView parent, final View item,
                          final int position, final long id)
  {
    // Figure out which item was clicked and take the appropriate action.
    switch (position)
    {
      case 0:
        search();
        break;
      case 1:
        editServer();
        break;
      case 2:
        removeServer();
        break;
    }
    finish();
  }



  /**
   * Displays the form to search the selected server instance.
   */
  private void search()
  {
    Intent i = new Intent(this, SearchServer.class);
    i.putExtra(SearchServer.BUNDLE_FIELD_INSTANCE, instance);
    startActivity(i);
  }



  /**
   * Displays the form to edit the specified server instance.
   */
  private void editServer()
  {
    Intent i = new Intent(this, EditServer.class);
    i.putExtra(EditServer.BUNDLE_FIELD_INSTANCE, instance);
    startActivity(i);
  }



  /**
   * Deletes the selected server instance.
   */
  private void removeServer()
  {
    String id = instance.getID();

    try
    {
      Map<String,ServerInstance> instances = ServerInstance.getInstances(this);
      LinkedHashMap<String,ServerInstance> newInstances =
           new LinkedHashMap<String,ServerInstance>(instances);
      newInstances.remove(id);

      ServerInstance.saveInstances(this, newInstances);

      Intent i = new Intent(this, PopUp.class);
      i.putExtra(PopUp.BUNDLE_FIELD_TITLE, "Server Removed");
      i.putExtra(PopUp.BUNDLE_FIELD_TEXT,
                 "Successfully removed server instance " + id + '.');
      startActivity(i);
    }
    catch (Exception e)
    {
      Intent i = new Intent(this, PopUp.class);
      i.putExtra(PopUp.BUNDLE_FIELD_TITLE, "ERROR");
      i.putExtra(PopUp.BUNDLE_FIELD_TEXT,
                 "Unable to remove server instance " + id + ":  " +
                 getExceptionMessage(e));
      startActivity(i);
    }
  }
}
