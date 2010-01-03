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



import java.util.HashSet;
import java.util.StringTokenizer;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.Gravity;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides an Android activity that may be used to view a search
 * result entry and handle the user clicking on various types of attributes.
 */
public class ViewEntry
       extends Activity
{
  /**
   * The name of the field used to define the instance to be searched.
   */
  public static final String BUNDLE_FIELD_ENTRY = "VIEW_ENTRY_ENTRY";



  /**
   * The name of the attribute used for the name.
   */
  static final String ATTR_NAME = "cn";



  /**
   * The name of the attribute used for the title.
   */
  static final String ATTR_TITLE = "title";



  /**
   * The name of the attribute used for the organization.
   */
  static final String ATTR_ORGANIZATION = "o";



  /**
   * The name of the attribute used for the primary telephone number, which
   * we will assume is the work number.
   */
  static final String ATTR_WORK_PHONE = "telephoneNumber";



  /**
   * The name of the attribute used for the mobile telephone number.
   */
  static final String ATTR_MOBILE_PHONE = "mobile";



  /**
   * The name of the attribute used for the home telephone number.
   */
  static final String ATTR_HOME_PHONE = "homePhone";



  /**
   * The name of the attribute used for the pager number.
   */
  static final String ATTR_PAGER = "pager";



  /**
   * The name of the attribute used for the fax number.
   */
  static final String ATTR_FAX = "facsimileTelephoneNumber";



  /**
   * The name of the attribute used for the primary e-mail address.
   */
  static final String ATTR_MAIL = "mail";



  /**
   * The name of the attribute used for an alternate e-mail address.
   */
  static final String ATTR_MAIL_ALTERNATE = "mailAlternateAddress";



  /**
   * The name of the attribute used for the primary address, which we will
   * assume is the work address.
   */
  static final String ATTR_WORK_ADDRESS = "postalAddress";



  /**
   * The name of the attribute used for the home address.
   */
  static final String ATTR_HOME_ADDRESS = "homePostalAddress";



  /**
   * The set of attributes for which we will have special handling.
   */
  private static final HashSet<String> SPECIAL_ATTRS =
       new HashSet<String>();

  static
  {
    SPECIAL_ATTRS.add(toLowerCase(ATTR_WORK_PHONE));
    SPECIAL_ATTRS.add(toLowerCase(ATTR_MOBILE_PHONE));
    SPECIAL_ATTRS.add(toLowerCase(ATTR_HOME_PHONE));
    SPECIAL_ATTRS.add(toLowerCase(ATTR_PAGER));
    SPECIAL_ATTRS.add(toLowerCase(ATTR_FAX));
    SPECIAL_ATTRS.add(toLowerCase(ATTR_MAIL));
    SPECIAL_ATTRS.add(toLowerCase(ATTR_MAIL_ALTERNATE));
    SPECIAL_ATTRS.add(toLowerCase(ATTR_WORK_ADDRESS));
    SPECIAL_ATTRS.add(toLowerCase(ATTR_HOME_ADDRESS));
  }



  // The entry to display.
  private Entry entry;



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

    setContentView(R.layout.viewentry);

    if (entry.hasObjectClass("person") &&
        entry.hasAttribute(ATTR_NAME))
    {
      displayUser();
    }
    else
    {
      displayGeneric();
    }
  }



  /**
   * Generates the display for a user entry.
   */
  private void displayUser()
  {
    String name = entry.getAttributeValue(ATTR_NAME);
    String title = entry.getAttributeValue(ATTR_TITLE);
    String organization = entry.getAttributeValue(ATTR_ORGANIZATION);

    setTitle("Entry for User " + name);
    boolean showAddToContacts = false;

    LinearLayout layout = (LinearLayout) findViewById(R.id.layout_entry);

    // Display the name, and optionally the title and/or organization at the top
    // of the pane.
    TextView nameView = new TextView(this);
    nameView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 24.0f);
    nameView.setText(name);
    nameView.setGravity(Gravity.CENTER);
    if ((title == null) && (organization == null))
    {
      nameView.setPadding(0, 10, 0, 20);
    }
    else
    {
      nameView.setPadding(0, 10, 0, 0);
    }
    layout.addView(nameView);

    if (title != null)
    {
      TextView titleView = new TextView(this);
      titleView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 20.0f);
      titleView.setText(title);
      titleView.setGravity(Gravity.CENTER);
      if (organization == null)
      {
        titleView.setPadding(0, 0, 0, 20);
      }
      else
      {
        titleView.setPadding(0, 0, 0, 0);
      }
      layout.addView(titleView);
    }

    if (organization != null)
    {
      TextView companyView = new TextView(this);
      companyView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 20.0f);
      companyView.setText(organization);
      companyView.setGravity(Gravity.CENTER);
      companyView.setPadding(0, 0, 0, 20);
      layout.addView(companyView);
    }


    // Display the phone numbers, if appropriate.
    Attribute workPhone = entry.getAttribute(ATTR_WORK_PHONE);
    Attribute mobile = entry.getAttribute(ATTR_MOBILE_PHONE);
    Attribute homePhone = entry.getAttribute(ATTR_HOME_PHONE);
    Attribute pager = entry.getAttribute(ATTR_PAGER);
    Attribute fax = entry.getAttribute(ATTR_FAX);
    if ((workPhone != null) || (mobile != null) || (homePhone != null) ||
        (pager != null) || (fax != null))
    {
      addHeader("Phone Numbers", layout);
      showAddToContacts = true;

      if (workPhone != null)
      {
        for (String s : workPhone.getValues())
        {
          addPhoneNumber(s, "Work", layout);
        }
      }

      if (mobile != null)
      {
        for (String s : mobile.getValues())
        {
          addPhoneNumber(s, "Mobile", layout);
        }
      }

      if (homePhone != null)
      {
        for (String s : homePhone.getValues())
        {
          addPhoneNumber(s, "Home", layout);
        }
      }

      if (pager != null)
      {
        for (String s : pager.getValues())
        {
          addPhoneNumber(s, "Pager", layout);
        }
      }

      if (fax!= null)
      {
        for (String s : fax.getValues())
        {
          addPhoneNumber(s, "Fax", layout);
        }
      }
    }

    // Display the e-mail addresses, if appropriate.
    Attribute mail = entry.getAttribute(ATTR_MAIL);
    Attribute mailAlternate = entry.getAttribute(ATTR_MAIL_ALTERNATE);
    if ((mail != null) || (mailAlternate != null))
    {
      addHeader("E-Mail Addresses", layout);
      showAddToContacts = true;

      if (mail != null)
      {
        for (String s : mail.getValues())
        {
          addEMailAddress(s, "Primary", layout);
        }
      }

      if (mailAlternate != null)
      {
        for (String s : mailAlternate.getValues())
        {
          addEMailAddress(s, "Alternate", layout);
        }
      }
    }

    // Display the postal addresses, if appropriate.
    Attribute workAddress = entry.getAttribute(ATTR_WORK_ADDRESS);
    Attribute homeAddress = entry.getAttribute(ATTR_HOME_ADDRESS);
    if ((workAddress != null) || (homeAddress != null))
    {
      addHeader("Postal Addresses", layout);
      showAddToContacts = true;

      if (workAddress != null)
      {
        for (String s : workAddress.getValues())
        {
          addPostalAddress(s, "Work", layout);
        }
      }

      if (homeAddress != null)
      {
        for (String s : homeAddress.getValues())
        {
          addPostalAddress(s, "Home", layout);
        }
      }
    }


    // Display all remaining attributes.
    addHeader("Other Attributes", layout);
    for (Attribute a : entry.getAttributes())
    {
      String attrName = a.getName();
      if ((a.hasValue() &&
          (! SPECIAL_ATTRS.contains(toLowerCase(attrName)))))
      {
        addGenericAttribute(a, layout);
      }
    }


    // If we should provide an "Add to Contacts" button, then do so.
    if (showAddToContacts)
    {
      LinearLayout l = new LinearLayout(this);
      l.setOrientation(LinearLayout.HORIZONTAL);
      l.setGravity(Gravity.CENTER);

      Button addToContactsButton = new Button(this);
      addToContactsButton.setText("Add to Contacts");
      addToContactsButton.setLayoutParams(new LinearLayout.LayoutParams(
           LinearLayout.LayoutParams.WRAP_CONTENT,
           LinearLayout.LayoutParams.WRAP_CONTENT));
      addToContactsButton.setOnClickListener(
           new AddToContactsOnClickListener(this, entry));
      l.addView(addToContactsButton);

      layout.addView(l);
    }
  }



  /**
   * Generates the display for a generic entry.
   */
  private void displayGeneric()
  {
    setTitle("Entry for User " + entry.getDN());

    LinearLayout layout = (LinearLayout) findViewById(R.id.layout_entry);

    // Display the attributes .
    addHeader("Entry Attributes", layout);
    for (Attribute a : entry.getAttributes())
    {
      if (a.hasValue())
      {
        addGenericAttribute(a, layout);
      }
    }
  }



  /**
   * Adds the specified header to the provided layout.
   *
   * @param  header  The text of the header to add.
   * @param  layout  The layout to which the header should be added.
   */
  private void addHeader(final String header, final LinearLayout layout)
  {
    TextView headerView = new TextView(this);
    headerView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 20.0f);
    headerView.setText(header);
    headerView.setPadding(0, 15, 0, 5);
    layout.addView(headerView);
  }



  /**
   * Adds a phone number to the provided layout.
   *
   * @param  number  The phone number to be added.
   * @param  type    The type of phone number to be added.
   * @param  layout  The layout to which the number should be added.
   */
  private void addPhoneNumber(final String number, final String type,
                              final LinearLayout layout)
  {
    PhoneNumberOnClickListener onClickListener =
         new PhoneNumberOnClickListener(this, number);

    LinearLayout line = new LinearLayout(this);
    line.setOrientation(LinearLayout.HORIZONTAL);
    line.setPadding(0, 5, 0, 5);

    TextView typeView = new TextView(this);
    typeView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12.0f);
    typeView.setText(type);
    typeView.setGravity(Gravity.LEFT);
    typeView.setLayoutParams(new LinearLayout.LayoutParams(
         LinearLayout.LayoutParams.WRAP_CONTENT,
         LinearLayout.LayoutParams.FILL_PARENT));
    line.addView(typeView);

    LinearLayout numberAndButton = new LinearLayout(this);
    numberAndButton.setOrientation(LinearLayout.HORIZONTAL);
    numberAndButton.setGravity(Gravity.RIGHT);
    numberAndButton.setLayoutParams(new LinearLayout.LayoutParams(
         LinearLayout.LayoutParams.FILL_PARENT,
         LinearLayout.LayoutParams.FILL_PARENT));

    TextView numberView = new TextView(this);
    numberView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16.0f);
    numberView.setText(number);
    numberView.setGravity(Gravity.RIGHT);
    numberView.setLayoutParams(new LinearLayout.LayoutParams(
         LinearLayout.LayoutParams.WRAP_CONTENT,
         LinearLayout.LayoutParams.FILL_PARENT));
    numberAndButton.addView(numberView);

    ImageButton callButton = new ImageButton(this);
    callButton.setImageResource(android.R.drawable.ic_menu_call);
    callButton.setOnClickListener(onClickListener);
    numberAndButton.addView(callButton);

    line.addView(numberAndButton);
    line.setOnClickListener(onClickListener);
    layout.addView(line);
  }



  /**
   * Adds an e-mail address to the provided layout.
   *
   * @param  address  The e-mail address to be added.
   * @param  type     The type of address to be added.
   * @param  layout   The layout to which the address should be added.
   */
  private void addEMailAddress(final String address, final String type,
                               final LinearLayout layout)
  {
    EMailOnClickListener onClickListener =
         new EMailOnClickListener(this, address);

    LinearLayout line = new LinearLayout(this);
    line.setOrientation(LinearLayout.HORIZONTAL);
    line.setPadding(0, 5, 0, 5);

    TextView typeView = new TextView(this);
    typeView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12.0f);
    typeView.setText(type);
    typeView.setGravity(Gravity.LEFT);
    typeView.setLayoutParams(new LinearLayout.LayoutParams(
         LinearLayout.LayoutParams.WRAP_CONTENT,
         LinearLayout.LayoutParams.FILL_PARENT));
    line.addView(typeView);

    LinearLayout addressAndButton = new LinearLayout(this);
    addressAndButton.setOrientation(LinearLayout.HORIZONTAL);
    addressAndButton.setGravity(Gravity.RIGHT);
    addressAndButton.setLayoutParams(new LinearLayout.LayoutParams(
         LinearLayout.LayoutParams.FILL_PARENT,
         LinearLayout.LayoutParams.FILL_PARENT));

    TextView addressView = new TextView(this);
    addressView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16.0f);
    addressView.setText(address);
    addressView.setGravity(Gravity.RIGHT);
    addressView.setLayoutParams(new LinearLayout.LayoutParams(
         LinearLayout.LayoutParams.WRAP_CONTENT,
         LinearLayout.LayoutParams.FILL_PARENT));
    addressAndButton.addView(addressView);

    ImageButton mailButton = new ImageButton(this);
    mailButton.setImageResource(android.R.drawable.ic_menu_send);
    mailButton.setOnClickListener(onClickListener);
    addressAndButton.addView(mailButton);

    line.addView(addressAndButton);
    line.setOnClickListener(onClickListener);
    layout.addView(line);
  }



  /**
   * Adds a postal address to the provided layout.
   *
   * @param  address  The postal address to be added.
   * @param  type     The type of address to be added.
   * @param  layout   The list to which the address should be added.
   */
  private void addPostalAddress(final String address, final String type,
                                final LinearLayout layout)
  {
    StringBuilder userFriendly = new StringBuilder();
    StringBuilder mapFriendly = new StringBuilder();
    StringTokenizer tokenizer = new StringTokenizer(address, "$");
    while (tokenizer.hasMoreTokens())
    {
      String token = tokenizer.nextToken().trim();
      userFriendly.append(token);
      mapFriendly.append(token);
      if (tokenizer.hasMoreTokens())
      {
        userFriendly.append(EOL);
        mapFriendly.append(' ');
      }
    }

    MapOnClickListener onClickListener =
         new MapOnClickListener(this, mapFriendly.toString());

    LinearLayout line = new LinearLayout(this);
    line.setOrientation(LinearLayout.HORIZONTAL);
    line.setPadding(0, 5, 0, 5);

    TextView typeView = new TextView(this);
    typeView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12.0f);
    typeView.setText(type);
    typeView.setGravity(Gravity.LEFT);
    typeView.setLayoutParams(new LinearLayout.LayoutParams(
         LinearLayout.LayoutParams.WRAP_CONTENT,
         LinearLayout.LayoutParams.FILL_PARENT));
    line.addView(typeView);

    LinearLayout addressAndButton = new LinearLayout(this);
    addressAndButton.setOrientation(LinearLayout.HORIZONTAL);
    addressAndButton.setGravity(Gravity.RIGHT);
    addressAndButton.setLayoutParams(new LinearLayout.LayoutParams(
         LinearLayout.LayoutParams.FILL_PARENT,
         LinearLayout.LayoutParams.FILL_PARENT));

    TextView addressView = new TextView(this);
    addressView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16.0f);
    addressView.setText(userFriendly.toString());
    addressView.setGravity(Gravity.RIGHT);
    addressView.setLayoutParams(new LinearLayout.LayoutParams(
         LinearLayout.LayoutParams.WRAP_CONTENT,
         LinearLayout.LayoutParams.FILL_PARENT));
    addressAndButton.addView(addressView);

    ImageButton mapButton = new ImageButton(this);
    mapButton.setImageResource(android.R.drawable.ic_menu_mapmode);
    mapButton.setOnClickListener(onClickListener);
    addressAndButton.addView(mapButton);

    line.addView(addressAndButton);
    line.setOnClickListener(onClickListener);
    layout.addView(line);
  }



  /**
   * Adds information about a generic attribute to the provided layout.
   *
   * @param  attribute  The attribute to be added.
   * @param  layout     The layout to which to add the attribute.
   */
  private void addGenericAttribute(final Attribute attribute,
                                   final LinearLayout layout)
  {
    String[] values = attribute.getValues();

    LinearLayout l = new LinearLayout(this);
    if (values.length == 1)
    {
      l.setPadding(0, 5, 0, 20);
    }
    else
    {
      l.setPadding(0, 5, 0, 5);
    }
    l.setOrientation(LinearLayout.HORIZONTAL);

    TextView nameView = new TextView(this);
    nameView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12.0f);
    nameView.setText(attribute.getName());
    nameView.setGravity(Gravity.LEFT);
    nameView.setLayoutParams(new LinearLayout.LayoutParams(
         LinearLayout.LayoutParams.WRAP_CONTENT,
         LinearLayout.LayoutParams.FILL_PARENT));
    l.addView(nameView);

    TextView valueView = new TextView(this);
    valueView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16.0f);
    valueView.setText(values[0]);
    valueView.setGravity(Gravity.RIGHT);
    valueView.setLayoutParams(new LinearLayout.LayoutParams(
         LinearLayout.LayoutParams.FILL_PARENT,
         LinearLayout.LayoutParams.FILL_PARENT));
    l.addView(valueView);

    layout.addView(l);

    for (int i=1; i < values.length; i++)
    {
      TextView additionalValueView = new TextView(this);
      additionalValueView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14.0f);
      additionalValueView.setText(values[i]);
      additionalValueView.setGravity(Gravity.RIGHT);

      if (i == (values.length - 1))
      {
        additionalValueView.setPadding(0, 5, 0, 20);
      }
      else
      {
        additionalValueView.setPadding(0, 5, 0, 5);
      }

      layout.addView(additionalValueView);
    }
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
   * Restores the state of this activity from the provided bundle.
   *
   * @param  state  The bundle containing the state information.
   */
  private void restoreState(final Bundle state)
  {
    entry = (Entry) state.getSerializable(BUNDLE_FIELD_ENTRY);
  }



  /**
   * Saves the state of this activity to the provided bundle.
   *
   * @param  state  The bundle containing the state information.
   */
  private void saveState(final Bundle state)
  {
    state.putSerializable(BUNDLE_FIELD_ENTRY, entry);
  }
}
