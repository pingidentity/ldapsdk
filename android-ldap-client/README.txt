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
map of that location.  If the entry contains any of the previously-mentioned
phone number, e-mail address, or postal address attributes, then a button will
also be displayed to allow that information to be added into the phone's
contacts database (i.e., address book).

In order to build this tool, you will need the Android SDK.  This code was
built and tested using the Android SDK version 1.0, Release 2, which is
available on Windows, Mac OS X, and Linux.  This code has been successfully
built on both Ubuntu Linux 08.10 and Windows XP Professional, and the compiled
package has been tested on the Android emulator on both those platforms as well
as on the Android Dev Phone 1.

To build this application, use the following steps:

1.  Go to the tools directory below the Android SDK installation and run the
    following command:
         ./activitycreator -o {wspath}/android-ldap-client \
              com.unboundid.android.ldap.browser.LDAPBrowser
    where {wspath} is the path to the desired workspace directory.

2.  Go to the {wspath}/android-ldap-client directory and remove the generated
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
     ./adb -e install {wspath}/AndroidLDAPBrowser/bin/LDAPBrowser-debug.apk


If the application is already installed and you want to re-install it, then add
the "-r" argument after the install subcommand, like:
     ./adb -e install -r {wspath}/AndroidLDAPBrowser/bin/LDAPBrowser-debug.apk


If you want to install the application on an Android device instead of in an
emulator, then use "-d" instead of "-e", like:
     ./adb -d install {wspath}/AndroidLDAPBrowser/bin/LDAPBrowser-debug.apk


Or to re-install the application on a device:
     ./adb -d install -r {wspath}/AndroidLDAPBrowser/bin/LDAPBrowser-debug.apk


Regardless of whether you're using the emulator or a device, you can uninstall
the application by going to the home screen, pressing the "MENU" key, choosing
the "Settings" option, "Applications", "Manage applications", and then
"UnboundID LDAP Client".  Click the "Uninstall" button to remove it.

In order to develop applications for Android, all that you technically need is
the Android SDK, a Java installation, and a text editor.  However, it is easier
if you use an IDE.  The Android SDK includes a plugin for Eclipse, but I was
unable to get it running on Ubuntu after a couple of attempts.  However, there
is also an "Android Support" plugin for IDEA that can be used to aid in
development and I was able to use it (at least as a code editor -- I used
command-line tools to build and deploy the application).  Once it is installed,
create a new project from scratch.  Specify the desired location for the
project and indicate that it should be a Java Module (which should be the
default) and click the Next button.  Indicate that you do wnat to create a
"src" directory and click Next.  On the "Please select the desired
technologies" pane, check the "Android" box and if necessary provide the path
to the Android SDK (choose the directory that is the parent of the docs,
samples, and tools subdirectories) and click Finish.  On the filesystem,
remove the AndroidManifest.xml file and the res and src directories.  Copy the
corresponding files from this commit (along with the libs directory) into the
IDEA project directory, and update the project settings to attach "libs" as a
Jar directory.

