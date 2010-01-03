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
import java.util.Arrays;
import java.util.HashMap;

import android.app.ListActivity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ArrayAdapter;
import android.widget.TextView;

import com.unboundid.ldap.sdk.SearchResultEntry;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides an Android activity that may be used to display the set
 * of entries returned from a search and choose an entry to view.
 */
public class ListSearchResults
       extends ListActivity
       implements OnItemClickListener
{
  /**
   * The name of the field used to define the instance to be searched.
   */
  public static final String BUNDLE_FIELD_INSTANCE = "LIST_RESULTS_INSTANCE";



  /**
   * The name of the field used to define the entries to list.
   */
  public static final String BUNDLE_FIELD_ENTRIES = "LIST_RESULTS_ENTRIES";



  // The list of entries to process.
  private ArrayList<SearchResultEntry> entries;

  // A map of the entry strings to their corresponding names.
  private HashMap<String,SearchResultEntry> entryMap;

  // The server instance to search.
  private ServerInstance instance;



  /**
   * Performs all necessary processing when this activity is created.
   *
   * @param  state  The state information for this activity.
   */
  @Override()
  protected void onCreate(final Bundle state)
  {
    super.onCreate(state);

    Intent i = getIntent();
    Bundle extras = i.getExtras();
    restoreState(extras);
  }



  /**
   * Performs all necessary processing when this activity is started or resumed.
   */
  @Override()
  protected void onResume()
  {
    super.onResume();

    setTitle("Search Results:  " + entries.size() + " Entries Returned");

    entryMap = new HashMap<String,SearchResultEntry>(entries.size());
    String[] entryStrings = new String[entries.size()];
    for (int i=0; i < entryStrings.length; i++)
    {
      SearchResultEntry e = entries.get(i);
      if (e.hasObjectClass("person"))
      {
        String name = e.getAttributeValue("cn");
        if (name == null)
        {
          entryStrings[i] = e.getDN();
        }
        else
        {
          StringBuilder buffer = new StringBuilder();
          buffer.append(name);

          String phone = e.getAttributeValue("telephoneNumber");
          if (phone != null)
          {
            buffer.append(EOL);
            buffer.append(phone);
          }

          String mail = e.getAttributeValue("mail");
          if (mail != null)
          {
            buffer.append(EOL);
            buffer.append(mail);
          }

          entryStrings[i] = buffer.toString();
        }
      }
      else
      {
        entryStrings[i] = e.getDN();
      }
      entryMap.put(entryStrings[i], e);
    }

    Arrays.sort(entryStrings);

    ArrayAdapter<String> adapter = new ArrayAdapter<String>(this,
         android.R.layout.simple_list_item_1, entryStrings);
    setListAdapter(adapter);
    getListView().setTextFilterEnabled(true);

    getListView().setOnItemClickListener(this);
  }



  /**
   * Performs all necessary processing when the instance state needs to be
   * saved.
   *
   * @param  state  The state information to be saved.
   */
  @Override()
  protected void onSaveInstanceState(final Bundle state)
  {
    saveState(state);
  }



  /**
   * Performs all necessary processing when the instance state needs to be
   * restored.
   *
   * @param  state  The state information to be restored.
   */
  @Override()
  protected void onRestoreInstanceState(final Bundle state)
  {
    restoreState(state);
  }



  /**
   * Takes any appropriate action after a list item has been clicked.
   *
   * @param  parent    The list in which the item was clicked.
   * @param  view      The list item that was clicked.
   * @param  position  The position of the item in the list that was clicked.
   * @param  id        The ID of the item that was clicked.
   */
  public void onItemClick(final AdapterView parent, final View view,
                          final int position, final long id)
  {
    TextView item = (TextView) view;
    SearchResultEntry e = entryMap.get(item.getText().toString());
    if (e != null)
    {
      Intent i = new Intent(this, ViewEntry.class);
      i.putExtra(ViewEntry.BUNDLE_FIELD_ENTRY, e);
      startActivity(i);
    }
  }



  /**
   * Restores the state of this activity from the provided bundle.
   *
   * @param  state  The bundle containing the state information.
   */
  private void restoreState(final Bundle state)
  {
    instance = (ServerInstance) state.getSerializable(BUNDLE_FIELD_INSTANCE);

    entries = new ArrayList<SearchResultEntry>();
    Object o = state.getSerializable(BUNDLE_FIELD_ENTRIES);
    if (o instanceof ArrayList)
    {
      ArrayList l = (ArrayList) o;
      entries.ensureCapacity(l.size());
      for (Object item : l)
      {
        entries.add((SearchResultEntry) item);
      }
    }
  }



  /**
   * Saves the state of this activity to the provided bundle.
   *
   * @param  state  The bundle containing the state information.
   */
  private void saveState(final Bundle state)
  {
    state.putSerializable(BUNDLE_FIELD_INSTANCE, instance);
    state.putSerializable(BUNDLE_FIELD_ENTRIES, entries);
  }
}
