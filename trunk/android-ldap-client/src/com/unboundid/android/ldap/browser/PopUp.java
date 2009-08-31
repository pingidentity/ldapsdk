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
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;



/**
 * This class provides an Android activity that may be used to display a message
 * in a pop-up dialog.
 */
public class PopUp
       extends Activity
       implements OnClickListener
{
  /**
   * The name of the field used to define the title for the pop-up dialog.
   */
  public static final String BUNDLE_FIELD_TITLE = "POP_UP_TITLE";



  /**
   * The name of the field used to define the text for the pop-up dialog.
   */
  public static final String BUNDLE_FIELD_TEXT = "POP_UP_TEXT";



  /**
   * Performs all necessary processing when this activity is started or resumed.
   */
  @Override()
  protected void onResume()
  {
    super.onResume();

    setContentView(R.layout.popup);


    // Set the appropriate content for this dialog.
    Intent intent = getIntent();
    Bundle extras = intent.getExtras();

    String title = extras.getString(BUNDLE_FIELD_TITLE);
    if (title == null)
    {
      title = "";
    }
    setTitle(title);

    String text  = extras.getString(BUNDLE_FIELD_TEXT);
    if (text == null)
    {
      text = "";
    }

    TextView v = (TextView) findViewById(R.id.popup_text);
    v.setText(text);


    // Add an on-click listener for the OK button.
    Button okButton = (Button) findViewById(R.id.button_ok);
    okButton.setOnClickListener(this);
  }



  /**
   * Takes any appropriate action after a button has been clicked.
   *
   * @param  view  The view for the button that was clicked.
   */
  public void onClick(final View view)
  {
    // There is only one button to click, and it's the OK button.  Close this
    // pop-up.
    finish();
  }
}
