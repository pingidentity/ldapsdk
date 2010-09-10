This directory contains the source for a simple application which runs on the
Android mobile device platform (http://code.google.com/android/).  It is a
tool that may be used to interact with a directory server to perform LDAP
searches and display the results to the user.

When viewing an entry, the user will be able to click on any of the values for
the telephoneNumber, homePhone, mobile, pager, and facsimileTelephoneNumber
attributes in order to be taken to the dialer to allow them to call that
number.  They will be able to click on any of the values for the mail and
mailAlternateAddress attributes in order to be able to begin composing an
e-mail message to that user.  They will be able to click on any of the values
for the postalAddress and homePostalAddress attributes in order to display a
map of or navigate to that location.  If the entry contains any of the
previously-mentioned phone number, e-mail address, or postal address
attributes, then a button will also be displayed to allow that information to
be added into the phone's contacts database (i.e., address book).  For any
attribute in the entry, you have the option to copy the value of that attribute
to the clipboard, and by clicking on the header at the top of the entry, you
can view the entry as LDIF, or copy the DN or LDIF representation to the
clipboard.

In order to build this tool, you will need the 2.2 or later version of the
Android SDK (although the resulting client will run on devices with Android 1.5
or later), available from http://www.android.com/.  Then, use the following
steps:

1.  Go to the tools directory below the Android SDK installation and run the
    following command:
         ./android create project --package com.unboundid.android.ldap.client \
              --name LDAPClient --activity LDAPClient --target 8 \
              --path {wspath}/AndroidLDAPClient
    where {wspath} is the path to the desired workspace directory.

2.  Go to the {wspath}/AndroidLDAPClient directory and remove the generated
    AndroidManifest.xml file and the entire res and src directories.  Replace
    them with the versions contained in this commit.  Place the UnboundID LDAP
    SDK for Java jar file in the {wspath}/android-ldap-client/libs directory.

3.  To build the application, simply invoke ant with no arguments.  If you
    have one instance of the emulator running and no Android devices connected,
    then you can install the application into the emulator using "ant install".
    If the application has already been installed and you want to update it,
    then use "ant reinstall".


Note that whenever you build the project, the R.java source file will be
automatically regenerated based on the files in the res directory.

To manually install the application in the emulator, you will need to first
launch the emulator (by running the tools/emulator program provided with the
Android LDAP SDK).  Then go to the tools directory in the Android SDK
installation and run the command:
     ./adb -e install {wspath}/AndroidLDAPClient/bin/LDAPClient-debug.apk


If the application is already installed and you want to re-install it, then add
the "-r" argument after the install subcommand, like:
     ./adb -e install -r {wspath}/AndroidLDAPClient/bin/LDAPClient-debug.apk


If you want to install the application on an Android device instead of in an
emulator, then use "-d" instead of "-e", like:
     ./adb -d install {wspath}/AndroidLDAPClient/bin/LDAPClient-debug.apk


Or to re-install the application on a device:
     ./adb -d install -r {wspath}/AndroidLDAPClient/bin/LDAPClient-debug.apk


Regardless of whether you're using the emulator or a device, you can uninstall
the application by going to the home screen, pressing the "MENU" key, choosing
the "Settings" option, "Applications", "Manage applications", and then
"LDAP Client".  Click the "Uninstall" button to remove it.

