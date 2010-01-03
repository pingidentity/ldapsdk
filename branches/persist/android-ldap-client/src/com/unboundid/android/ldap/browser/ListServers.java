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



import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.StringTokenizer;

import android.app.Activity;
import android.content.Intent;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.AdapterView.OnItemLongClickListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.TextView;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides an Android activity that may be used to list the set of
 * available directory servers and choose to search a server, define a new
 * server, edit a server, or remove a server.
 */
public class ListServers
       extends Activity
       implements OnClickListener, OnItemClickListener,
                  OnItemLongClickListener
{
  // The set of defined server instances.
  private Map<String,ServerInstance> instances;



  /**
   * Performs all necessary processing when this activity is started or resumed.
   */
  @Override()
  protected void onResume()
  {
    super.onResume();

    setContentView(R.layout.listservers);
    setTitle(getString(R.string.label_available_servers));


    // Get the list of defined instances.
    try
    {
      instances = ServerInstance.getInstances(this);
    }
    catch (Exception e)
    {
      Intent i = new Intent(this, PopUp.class);
      i.putExtra(PopUp.BUNDLE_FIELD_TITLE, "ERROR");
      i.putExtra(PopUp.BUNDLE_FIELD_TEXT,
                 "An error occurred while trying to obtain the list of " +
                 "defined servers:  " + getExceptionMessage(e));
      startActivity(i);

      instances = Collections.emptyMap();
    }


    // Populate the list of servers.
    ArrayList<String> listStrings = new ArrayList<String>();
    for (ServerInstance i : instances.values())
    {
      StringBuilder buffer = new StringBuilder();
      buffer.append(i.getID());
      buffer.append(EOL);
      buffer.append(i.getHost());
      buffer.append(':');
      buffer.append(i.getPort());

      if (i.useSSL())
      {
        buffer.append(" (using SSL)");
      }
      else if (i.useStartTLS())
      {
        buffer.append(" (using StartTLS)");
      }

      listStrings.add(buffer.toString());
    }

    ListView serverList = (ListView) findViewById(R.id.list_servers);
    ArrayAdapter<String> listAdapter = new ArrayAdapter<String>(this,
         android.R.layout.simple_list_item_1, listStrings);
    serverList.setAdapter(listAdapter);
    serverList.setTextFilterEnabled(true);
    serverList.setOnItemClickListener(this);
    serverList.setOnItemLongClickListener(this);


    // Add an on-click listener to the "Define a New Server" button.
    Button addButton = (Button) findViewById(R.id.button_new_server);
    addButton.setOnClickListener(this);
    addButton.setEnabled(true);
  }



  /**
   * Takes any appropriate action after a button has been clicked.
   *
   * @param  view  The view for the button that was clicked.
   */
  public void onClick(final View view)
  {
    // This must have been the "Define a New Server
    switch (view.getId())
    {
      case R.id.button_new_server:
        Intent i = new Intent(this, AddServer.class);
        startActivity(i);
        break;
    }
  }



  /**
   * Takes any appropriate action after a list item has been clicked.
   *
   * @param  parent    The view for the list in which the item exists.
   * @param  view      The view for the item that was clicked.
   * @param  position  The position of the item in the list.
   * @param  id        The ID of the item that was clicked.
   */
  public void onItemClick(final AdapterView parent, final View view,
                          final int position, final long id)
  {
    TextView textView = (TextView) view;
    StringTokenizer tokenizer =
         new StringTokenizer(textView.getText().toString(), "\r\n");
    ServerInstance instance = instances.get(tokenizer.nextToken());
    search(instance);
  }



  /**
   * Takes any appropriate action after a list item has been clicked.
   *
   * @param  parent    The view for the list in which the item exists.
   * @param  view      The view for the item that was clicked.
   * @param  position  The position of the item in the list.
   * @param  id        The ID of the item that was clicked.
   *
   * @return  {@code true} if this method consumed the click, or {@code false}
   *          if not.
   */
  public boolean onItemLongClick(final AdapterView parent, final View view,
                                 final int position, final long id)
  {
    TextView textView = (TextView) view;
    StringTokenizer tokenizer =
         new StringTokenizer(textView.getText().toString(), "\r\n");
    ServerInstance instance = instances.get(tokenizer.nextToken());

    Intent i = new Intent(this, ListServerOptions.class);
    i.putExtra(ListServerOptions.BUNDLE_FIELD_INSTANCE, instance);
    startActivity(i);
    return true;
  }



  /**
   * Displays the form to search the selected server instance.
   *
   * @param  instance  The instance in which to perform the search.
   */
  private void search(final ServerInstance instance)
  {
    Intent i = new Intent(this, SearchServer.class);
    i.putExtra(SearchServer.BUNDLE_FIELD_INSTANCE, instance);
    startActivity(i);
  }
}
