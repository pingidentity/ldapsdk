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
import java.util.LinkedHashMap;
import java.util.List;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides an Android activity that may be used to define a new
 * directory server.
 */
public class AddServer
       extends Activity
       implements OnClickListener
{
  /**
   * The name of the field used to define the server ID.
   */
  public static final String BUNDLE_FIELD_ID = "ADD_SERVER_ID";



  /**
   * The name of the field used to define the server address.
   */
  public static final String BUNDLE_FIELD_HOST = "ADD_SERVER_HOST";



  /**
   * The name of the field used to define the server port.
   */
  public static final String BUNDLE_FIELD_PORT = "ADD_SERVER_PORT";



  /**
   * The name of the field used to define the security method.
   */
  public static final String BUNDLE_FIELD_SECURITY = "ADD_SERVER_SECURITY";



  /**
   * The name of the field used to define the bind DN.
   */
  public static final String BUNDLE_FIELD_BIND_DN = "ADD_SERVER_BIND_DN";



  /**
   * The name of the field used to define the bind password.
   */
  public static final String BUNDLE_FIELD_BIND_PW = "ADD_SERVER_BIND_PW";



  /**
   * The name of the field used to define the base DN.
   */
  public static final String BUNDLE_FIELD_BASE_DN = "ADD_SERVER_BASE_DN";



  // Indicates whether to use SSL.
  private boolean useSSL = false;

  // Indicates whether to use StartTLS.
  private boolean useStartTLS = false;

  // The server port.
  private int port = 389;

  // The progress dialog displayed while the search is in progress.
  private volatile ProgressDialog progressDialog;

  // The server base DN.
  private String baseDN = "";

  // The bind DN.
  private String bindDN;

  // The bind password.
  private String bindPW = "";

  // The server address.
  private String host = "";

  // The server ID.
  private String id = "";



  /**
   * Performs all necessary processing when this activity is created.
   *
   * @param  state  The state information for this activity.
   */
  @Override()
  protected void onCreate(final Bundle state)
  {
    super.onCreate(state);

    if (state != null)
    {
      restoreState(state);
    }
  }



  /**
   * Performs all necessary processing when this activity is started or resumed.
   */
  @Override()
  protected void onResume()
  {
    super.onResume();

    setContentView(R.layout.defineserver);

    // Populate the server ID.
    EditText idField = (EditText) findViewById(R.id.field_id);
    idField.setText(id);

    // Populate the server address.
    EditText hostField = (EditText) findViewById(R.id.field_host);
    hostField.setText(host);

    // Populate the server port.
    EditText portField = (EditText) findViewById(R.id.field_port);
    portField.setText(String.valueOf(port));

    // Populate the list of available security mechanisms.
    Spinner secSpinner = (Spinner) findViewById(R.id.spinner_security);
    ArrayAdapter<CharSequence> secAdapter = ArrayAdapter.createFromResource(
         this, R.array.security_list, android.R.layout.simple_spinner_item);
    secAdapter.setDropDownViewResource(
         android.R.layout.simple_spinner_dropdown_item);
    secSpinner.setAdapter(secAdapter);
    if (useSSL)
    {
      secSpinner.setSelection(1);
    }
    else if (useStartTLS)
    {
      secSpinner.setSelection(2);
    }
    else
    {
      secSpinner.setSelection(0);
    }

    // Populate the bind DN.
    EditText bindDNField = (EditText) findViewById(R.id.field_bind_dn);
    bindDNField.setText(bindDN);

    // Populate the bind Password.
    EditText bindPWField = (EditText) findViewById(R.id.field_bind_pw);
    bindPWField.setText(bindPW);

    // Populate the base DN.
    EditText baseDNField = (EditText) findViewById(R.id.field_base);
    baseDNField.setText(baseDN);

    // Add an on-click listener to the test and save buttons.
    Button testButton = (Button) findViewById(R.id.button_server_test);
    testButton.setOnClickListener(this);

    Button saveButton = (Button) findViewById(R.id.button_server_save);
    saveButton.setOnClickListener(this);
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
   * Takes any appropriate action after a button has been clicked.
   *
   * @param  view  The view for the button that was clicked.
   */
  public void onClick(final View view)
  {
    // Figure out which button was clicked and take the appropriate action.
    switch (view.getId())
    {
      case R.id.button_server_test:
        testSettings();
        break;

      case R.id.button_server_save:
        saveSettings();
        break;
    }
  }



  /**
   * Creates a new {@code ServerInstance} structure from the provided
   * information.
   *
   * @return  The created {@code ServerInstance} structure.
   *
   * @throws  NumberFormatException  If the port number is not an integer.
   */
  private ServerInstance createInstance()
          throws NumberFormatException
  {
    EditText idField = (EditText) findViewById(R.id.field_id);
    String serverID = idField.getText().toString();

    EditText hostField = (EditText) findViewById(R.id.field_host);
    host = hostField.getText().toString();

    EditText portField = (EditText) findViewById(R.id.field_port);
    port = Integer.parseInt(portField.getText().toString());

    useSSL = false;
    useStartTLS = false;
    Spinner secSpinner = (Spinner) findViewById(R.id.spinner_security);
    switch (secSpinner.getSelectedItemPosition())
    {
      case 1:
        useSSL = true;
        break;
      case 2:
        useStartTLS = true;
        break;
    }

    EditText bindDNField = (EditText) findViewById(R.id.field_bind_dn);
    bindDN = bindDNField.getText().toString();

    EditText bindPWField = (EditText) findViewById(R.id.field_bind_pw);
    bindPW = bindPWField.getText().toString();

    EditText baseField = (EditText) findViewById(R.id.field_base);
    baseDN = baseField.getText().toString();

    return new ServerInstance(serverID, host, port, useSSL, useStartTLS,
                              bindDN, bindPW, baseDN);
  }



  /**
   * Tests the provided server settings to determine if they are acceptable.
   */
  private void testSettings()
  {
    ArrayList<String> reasons = new ArrayList<String>();

    ServerInstance instance = null;
    try
    {
      instance = createInstance();
    }
    catch (NumberFormatException nfe)
    {
      reasons.add("The port number must be an integer.");

      Intent i = new Intent(this, PopUp.class);
      i.putExtra(PopUp.BUNDLE_FIELD_TITLE, "Test Failed");
      i.putExtra(PopUp.BUNDLE_FIELD_TEXT,
                 "The provided server settings are not acceptable or the " +
                 "server is unavailable.  The failure reasons are:  " +
                 listToString(reasons));
      startActivity(i);
      return;
    }

    // Create and start a thread to test the server settings.
    TestServerThread testThread = new TestServerThread(this, instance);
    testThread.start();

    // Create a progress dialog to display while the search is in progress.
    progressDialog = new ProgressDialog(this);
    progressDialog.setTitle("Testing Server Settings...");
    progressDialog.setIndeterminate(true);
    progressDialog.setCancelable(false);
    progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
    progressDialog.show();
  }



  /**
   * Indicates that the server test has completed.
   *
   * @param  acceptable  Indicates that the instance appears to be acceptable.
   * @param  reasons     Reasons that the instance was not acceptable.
   */
  void testCompleted(final boolean acceptable, final ArrayList<String> reasons)
  {
    progressDialog.dismiss();

    if (acceptable)
    {
      Intent i = new Intent(this, PopUp.class);
      i.putExtra(PopUp.BUNDLE_FIELD_TITLE, "Test Successful");
      i.putExtra(PopUp.BUNDLE_FIELD_TEXT,
                 "The provided server settings appear to be acceptable.");
      startActivity(i);
    }
    else
    {
      Intent i = new Intent(this, PopUp.class);
      i.putExtra(PopUp.BUNDLE_FIELD_TITLE, "Test Failed");
      i.putExtra(PopUp.BUNDLE_FIELD_TEXT,
                 "The provided server settings are not acceptable or the " +
                 "server is unavailable.  The failure reasons are:  " +
                 listToString(reasons));
      startActivity(i);
    }
  }



  /**
   * Saves the provided server settings.
   */
  private void saveSettings()
  {
    boolean acceptable;
    ArrayList<String> reasons = new ArrayList<String>();

    ServerInstance instance = null;
    try
    {
      instance   = createInstance();
      acceptable = instance.isDefinitionValid(reasons);
    }
    catch (NumberFormatException nfe)
    {
      acceptable = false;
      reasons.add("The port number must be an integer.");
    }

    if (acceptable)
    {
      String instanceID = instance.getID();

      try
      {
        LinkedHashMap<String,ServerInstance> instanceMap =
             new LinkedHashMap<String,ServerInstance>(
                      ServerInstance.getInstances(this));
        if (instanceMap.containsKey(instanceID))
        {
          acceptable = false;
          reasons.add("Another server already exists with a server ID '" +
                      instanceID + '\'');
        }
        else
        {
          instanceMap.put(instanceID, instance);
          ServerInstance.saveInstances(this, instanceMap);
        }

        if (acceptable)
        {
          finish();
          return;
        }
      }
      catch (Exception e)
      {
        acceptable = false;
        reasons.add(getExceptionMessage(e));
      }
    }

    Intent i = new Intent(this, PopUp.class);
    i.putExtra(PopUp.BUNDLE_FIELD_TITLE, "Test Failed");
    i.putExtra(PopUp.BUNDLE_FIELD_TEXT,
               "The provided server settings are not acceptable or the " +
               "server is unavailable.  The failure reasons are:  " +
               listToString(reasons));
    startActivity(i);
  }



  /**
   * Restores the state of this activity from the provided bundle.
   *
   * @param  state  The bundle containing the state information.
   */
  private void restoreState(final Bundle state)
  {
    id = state.getString(BUNDLE_FIELD_ID);
    if (id == null)
    {
      id = "";
    }

    host = state.getString(BUNDLE_FIELD_HOST);
    if (host == null)
    {
      host = "";
    }

    port = state.getInt(BUNDLE_FIELD_PORT);
    if (port <= 0)
    {
      port = 389;
    }

    switch (state.getInt(BUNDLE_FIELD_SECURITY))
    {
      case 1:
        useSSL = true;
        useStartTLS = false;
        break;
      case 2:
        useSSL = false;
        useStartTLS = true;
        break;
      default:
        useSSL = false;
        useStartTLS = false;
        break;
    }

    bindDN = state.getString(BUNDLE_FIELD_BIND_DN);
    if (bindDN == null)
    {
      bindDN = "";
    }

    bindPW = state.getString(BUNDLE_FIELD_BIND_PW);
    if (bindPW == null)
    {
      bindPW = "";
    }

    baseDN = state.getString(BUNDLE_FIELD_BASE_DN);
    if (baseDN == null)
    {
      baseDN = "";
    }
  }



  /**
   * Saves the state of this activity to the provided bundle.
   *
   * @param  state  The bundle containing the state information.
   */
  private void saveState(final Bundle state)
  {
    EditText idField = (EditText) findViewById(R.id.field_id);
    id = idField.getText().toString();
    state.putString(BUNDLE_FIELD_ID, id);

    EditText hostField = (EditText) findViewById(R.id.field_host);
    host = hostField.getText().toString();
    state.putString(BUNDLE_FIELD_HOST, host);

    EditText portField = (EditText) findViewById(R.id.field_port);
    try
    {
      port = Integer.parseInt(portField.getText().toString());
    }
    catch (NumberFormatException nfe)
    {
      port = 389;
    }
    state.putInt(BUNDLE_FIELD_PORT, port);

    Spinner secSpinner = (Spinner) findViewById(R.id.spinner_security);
    int secVal = secSpinner.getSelectedItemPosition();
    switch (secVal)
    {
      case 1:
        useSSL      = true;
        useStartTLS = false;
        break;
      case 2:
        useSSL      = false;
        useStartTLS = true;
        break;
      default:
        useSSL      = false;
        useStartTLS = false;
        break;
    }
    state.putInt(BUNDLE_FIELD_SECURITY, secVal);

    EditText bindDNField = (EditText) findViewById(R.id.field_bind_dn);
    bindDN = bindDNField.getText().toString();
    state.putString(BUNDLE_FIELD_BIND_DN, bindDN);

    EditText bindPWField = (EditText) findViewById(R.id.field_bind_pw);
    bindPW = bindPWField.getText().toString();
    state.putString(BUNDLE_FIELD_BIND_PW, bindPW);

    EditText baseDNField = (EditText) findViewById(R.id.field_base);
    baseDN = baseDNField.getText().toString();
    state.putString(BUNDLE_FIELD_BASE_DN, baseDN);
  }



  /**
   * Retrieves a string representation of the contents of the provided list.
   *
   * @param  l  The list from which to take the elements.
   *
   * @return  A string representation of the contents of the provided list.
   */
  private static String listToString(final List<String> l)
  {
    StringBuilder buffer = new StringBuilder();
    for (String s : l)
    {
      buffer.append(EOL);
      buffer.append(EOL);
      buffer.append("- ");
      buffer.append(s);
    }

    return buffer.toString();
  }
}
