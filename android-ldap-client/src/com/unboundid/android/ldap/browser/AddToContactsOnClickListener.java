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



import java.util.StringTokenizer;

import android.app.Activity;
import android.content.ContentValues;
import android.content.Intent;
import android.net.Uri;
import android.provider.Contacts;
import android.view.View;
import android.view.View.OnClickListener;

import com.unboundid.ldap.sdk.Entry;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides an on-click listener that is meant to add a user to the
 * phone's address book when the associated view is clicked.
 */
class AddToContactsOnClickListener
      implements OnClickListener
{
  // The activity that created this on-click listener.
  private final Activity activity;

  // The information about the person to add.
  private final String fax;
  private final String homeAddress;
  private final String homeEMail;
  private final String homePhone;
  private final String mobile;
  private final String name;
  private final String pager;
  private final String workAddress;
  private final String workEMail;
  private final String workPhone;



  /**
   * Creates a new phone number on-click listener that will dial the provided
   * telephone number when the associated view is clicked.
   *
   * @param  activity  The activity that created this on-click listener.
   * @param  entry     The entry for the user to add.
   */
  public AddToContactsOnClickListener(final Activity activity,
                                      final Entry entry)
  {
    this.activity     = activity;

    name        = entry.getAttributeValue(ViewEntry.ATTR_NAME);
    workPhone   = entry.getAttributeValue(ViewEntry.ATTR_WORK_PHONE);
    homePhone   = entry.getAttributeValue(ViewEntry.ATTR_HOME_PHONE);
    mobile      = entry.getAttributeValue(ViewEntry.ATTR_MOBILE_PHONE);
    pager       = entry.getAttributeValue(ViewEntry.ATTR_PAGER);
    fax         = entry.getAttributeValue(ViewEntry.ATTR_FAX);
    workEMail   = entry.getAttributeValue(ViewEntry.ATTR_MAIL);
    homeEMail   = entry.getAttributeValue(ViewEntry.ATTR_MAIL_ALTERNATE);
    workAddress = entry.getAttributeValue(ViewEntry.ATTR_WORK_ADDRESS);
    homeAddress = entry.getAttributeValue(ViewEntry.ATTR_HOME_ADDRESS);
  }



  /**
   * Indicates that the associated view was clicked and that the associated
   * number should be dialed.
   *
   * @param  view  The view that was clicked.
   */
  public void onClick(final View view)
  {
    ContentValues values = new ContentValues();
    values.put(Contacts.People.NAME, name);
    values.put(Contacts.People.STARRED, 0);

    Uri contactURI = Contacts.People.createPersonInMyContactsGroup(
         activity.getContentResolver(), values);
    if (contactURI == null)
    {
      Intent i = new Intent(activity, PopUp.class);
      i.putExtra(PopUp.BUNDLE_FIELD_TITLE, "ERROR");
      i.putExtra(PopUp.BUNDLE_FIELD_TEXT,
                 "Unable to add user " + name + " to the contacts.");
      activity.startActivity(i);
    }
    else
    {
      if (workPhone != null)
      {
        addPhoneNumber(workPhone, Contacts.Phones.TYPE_WORK, contactURI);
      }

      if (homePhone != null)
      {
        addPhoneNumber(homePhone, Contacts.Phones.TYPE_HOME, contactURI);
      }

      if (mobile != null)
      {
        addPhoneNumber(mobile, Contacts.Phones.TYPE_MOBILE, contactURI);
      }

      if (pager != null)
      {
        addPhoneNumber(pager, Contacts.Phones.TYPE_PAGER, contactURI);
      }

      if (fax != null)
      {
        addPhoneNumber(fax, Contacts.Phones.TYPE_FAX_WORK, contactURI);
      }

      if (workEMail != null)
      {
        addEMailAddress(workEMail,
             Contacts.People.ContactMethods.TYPE_WORK, contactURI);
      }

      if (homeEMail != null)
      {
        addEMailAddress(homeEMail,
             Contacts.People.ContactMethods.TYPE_HOME, contactURI);
      }

      if (workAddress != null)
      {
        addPostalAddress(workAddress,
             Contacts.People.ContactMethods.TYPE_WORK, contactURI);
      }

      if (homeAddress != null)
      {
        addPostalAddress(homeAddress,
             Contacts.People.ContactMethods.TYPE_HOME, contactURI);
      }

      Intent i = new Intent(Intent.ACTION_VIEW, contactURI);
      activity.startActivity(i);
    }
  }



  /**
   * Adds the provided phone number to the contact.
   *
   * @param  number  The number to add.
   * @param  type    The type of number to add.
   * @param  uri     The base URI for the contact.
   *
   * @return  {@code true} if the update was successful, or {@code false} if
   *          not.
   */
  private boolean addPhoneNumber(final String number, final int type,
                                 final Uri uri)
  {
    Uri phoneURI =
         Uri.withAppendedPath(uri, Contacts.People.Phones.CONTENT_DIRECTORY);

    ContentValues values = new ContentValues();
    values.put(Contacts.Phones.TYPE, type);
    values.put(Contacts.Phones.NUMBER,  number);

    return (activity.getContentResolver().insert(phoneURI, values) != null);
  }



  /**
   * Adds the provided e-mail address to the contact.
   *
   * @param  address  The e-mail address to add.
   * @param  type     The type of address to add.
   * @param  uri      The base URI for the contact.
   *
   * @return  {@code true} if the update was successful, or {@code false} if
   *          not.
   */
  private boolean addEMailAddress(final String address, final int type,
                                  final Uri uri)
  {
    Uri emailURI = Uri.withAppendedPath(uri,
         Contacts.People.ContactMethods.CONTENT_DIRECTORY);

    ContentValues values = new ContentValues();
    values.put(Contacts.People.ContactMethods.KIND, Contacts.KIND_EMAIL);
    values.put(Contacts.People.ContactMethods.DATA, address);
    values.put(Contacts.People.ContactMethods.TYPE, type);

    return (activity.getContentResolver().insert(emailURI, values) != null);
  }



  /**
   * Adds the provided postal address to the contact.
   *
   * @param  address  The postal address to add.
   * @param  type     The type of address to add.
   * @param  uri      The base URI for the contact.
   *
   * @return  {@code true} if the update was successful, or {@code false} if
   *          not.
   */
  private boolean addPostalAddress(final String address, final int type,
                                   final Uri uri)
  {
    StringBuilder addr = new StringBuilder();
    StringTokenizer tokenizer = new StringTokenizer(address, "$");
    while (tokenizer.hasMoreTokens())
    {
      addr.append(tokenizer.nextToken().trim());
      if (tokenizer.hasMoreTokens())
      {
        addr.append(EOL);
      }
    }

    Uri postalURI = Uri.withAppendedPath(uri,
         Contacts.People.ContactMethods.CONTENT_DIRECTORY);

    ContentValues values = new ContentValues();
    values.put(Contacts.People.ContactMethods.KIND, Contacts.KIND_POSTAL);
    values.put(Contacts.People.ContactMethods.DATA, addr.toString());
    values.put(Contacts.People.ContactMethods.TYPE, type);

    return (activity.getContentResolver().insert(postalURI, values) != null);
  }
}
