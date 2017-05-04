/*
 * Copyright 2009-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2017 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.examples;



import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Random;
import java.util.zip.GZIPOutputStream;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the {@code SummarizeAccessLog}
 * class.
 */
public class SummarizeAccessLogTestCase
       extends LDAPSDKTestCase
{
  // The data files to use.
  private File dataFile1;
  private File dataFile2;
  private File longFilterFile;
  private File compressedFile;

  // The timestamp used for the last message.
  private long lastTimestamp;

  // The random number generator to use.
  private Random random;

  // The date formatter to use.
  private SimpleDateFormat dateFormat;



  /**
   * Creates a data file that will be used for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    random        = new Random();
    dateFormat    = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    lastTimestamp = System.currentTimeMillis();

    String[] lines =
    {
         "# This is a comment and the next line is empty",
         "",
         ts() + " INVALID",
         ts() + " CONNECT instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 from=\"1.2.3.4\" to=\"5.6.7.8\" " +
               "protocol=\"LDAP\" clientConnectionPolicy=\"default\"",
         ts() + " DISCONNECT instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 reason=\"Client Unbind\" " +
               "msg=\"The client has closed the connection\"",
         ts() + " DISCONNECT instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 reason=\"Client Unbind\" " +
               "msg=\"The client has closed the connection\"",
         ts() + " ABANDON REQUEST instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "idToAbandon=4",
         ts() + " ABANDON FORWARD instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "idToAbandon=4 targetHost=\"5.6.7.8\" targetPort=389 " +
               "targetProtocol=\"LDAP\"",
         ts() + " ABANDON RESULT instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "idToAbandon=4 resultCode=121 " +
               "message=\"This request cannot be canceled\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\"",
         ts() + " ADD REQUEST instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "dn=\"dc=example,dc=com\"",
         ts() + " ADD FORWARD instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "dn=\"dc=example,dc=com\" targetHost=\"5.6.7.8\" " +
               "targetPort=389 targetProtocol=\"LDAP\"",
         ts() + " ADD RESULT instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "dn=\"ou=People,dc=example,dc=com\" resultCode=32 " +
               "message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\" " +
               "uncachedDataAccessed=true",
         ts() + " BIND REQUEST instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" version=3 " +
               "dn=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "authType=\"INTERNAL\"",
         ts() + " BIND FORWARD instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" version=3 " +
               "dn=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "authType=\"INTERNAL\" targetHost=\"5.6.7.8\" targetPort=389 " +
               "targetProtocol=\"LDAP\"",
         ts() + " BIND RESULT instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" version=3 " +
               "dn=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "authType=\"SIMPLE\" resultCode=49 " +
               "message=\"Invalid credentials\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "authFailureID=1234 authFailureReason=\"Wrong password\" " +
               "authDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\" " +
               "clientConnectionPolicy=\"bind\" uncachedDataAccessed=true",
         ts() + " COMPARE REQUEST instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "dn=\"dc=example,dc=com\" attr=\"description\"",
         ts() + " COMPARE FORWARD instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "dn=\"dc=example,dc=com\" attr=\"description\" " +
               "targetHost=\"5.6.7.8\" targetPort=389 targetProtocol=\"LDAP\"",
         ts() + " COMPARE RESULT instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "dn=\"ou=People,dc=example,dc=com\" attr=\"description\" " +
               "resultCode=32 message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\" " +
               "uncachedDataAccessed=true",
         ts() + " DELETE REQUEST instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "dn=\"dc=example,dc=com\"",
         ts() + " DELETE FORWARD instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "dn=\"dc=example,dc=com\" targetHost=\"5.6.7.8\" " +
               "targetPort=389 targetProtocol=\"LDAP\"",
         ts() + " DELETE RESULT instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "dn=\"ou=People,dc=example,dc=com\" resultCode=32 " +
               "message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\" " +
               "uncachedDataAccessed=true",
         ts() + " EXTENDED REQUEST instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "requestOID=\"5.6.7.8\"",
         ts() + " EXTENDED FORWARD instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "requestOID=\"4.3.2.1\" targetHost=\"5.6.7.8\" " +
               "targetPort=389 targetProtocol=\"LDAP\"",
         ts() + " EXTENDED RESULT instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "requestOID=\"5.6.7.8\" resultCode=32 " +
               "message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "responseOID=\"8.7.6.5\" clientConnectionPolicy=\"extended\" " +
               "uncachedDataAccessed=true",
         ts() + " MODIFY REQUEST instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "dn=\"dc=example,dc=com\"",
         ts() + " MODIFY FORWARD instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "dn=\"dc=example,dc=com\" targetHost=\"5.6.7.8\" " +
               "targetPort=389 targetProtocol=\"LDAP\"",
         ts() + " MODIFY RESULT " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "dn=\"ou=People,dc=example,dc=com\" resultCode=32 " +
               "message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\" " +
               "uncachedDataAccessed=true",
         ts() + " MODDN REQUEST instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "dn=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "newRDN=\"uid=test.user\" deleteOldRDN=false " +
               "newSuperior=\"ou=Users,dc=example,dc=com\"",
         ts() + " MODDN FORWARD instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "dn=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "newRDN=\"uid=test.user\" deleteOldRDN=false " +
               "newSuperior=\"ou=Users,dc=example,dc=com\" " +
               "targetHost=\"5.6.7.8\" targetPort=389 targetProtocol=\"LDAP\"",
         ts() + " MODDN RESULT instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "dn=\"ou=People,dc=example,dc=com\" newRDN=\"ou=Users\" " +
               "deleteOldRDN=true newSuperior=\"o=example.com\" " +
               "resultCode=32 message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\" " +
               "uncachedDataAccessed=true",
         ts() + " SEARCH REQUEST " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "base=\"dc=example,dc=com\" scope=2 " +
               "filter=\"(uid=test.user)\" attrs=\"givenName,sn\"",
         ts() + " SEARCH FORWARD instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "base=\"dc=example,dc=com\" scope=2 " +
               "filter=\"(uid=test.user)\" attrs=\"cn\" " +
               "targetHost=\"5.6.7.8\" targetPort=389 targetProtocol=\"LDAP\"",
         ts() + " SEARCH ENTRY instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" dn=\"dc=example,dc=com\"",
         ts() + " SEARCH REFERENCE instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" " +
               "referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\"",
         ts() + " SEARCH RESULT instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "base=\"ou=People,dc=example,dc=com\" scope=0 " +
               "filter=\"(objectClass=*)\" attrs=\"ALL\" resultCode=32 " +
               "message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" entriesReturned=1 " +
               "unindexed=true " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\" " +
               "uncachedDataAccessed=true",
         ts() + " UNBIND REQUEST instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "dn=\"dc=example,dc=com\"",
         ts() + " EXTENDED REQUEST conn=1 op=2 msgID=3 requestOID=\"5.6.7.8\"",
         ts() + " EXTENDED RESULT conn=1 op=2 msgID=3 resultCode=32 " +
               "message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "responseOID=\"8.7.6.5\"",
         ts() + " EXTENDED RESULT conn=1 op=2 msgID=3 resultCode=32 " +
               "message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "responseOID=\"8.7.6.5\"",
         ts() + " EXTENDED RESULT instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "requestOID=\"5.6.7.8\" resultCode=32 " +
               "message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "responseOID=\"8.7.6.5\"",
         ts() + " SEARCH REQUEST base=\"dc=example,dc=com\" scope=2 " +
               "filter=\"(uid=test.user)\" attrs=\"givenName,sn\"",
         ts() + " SEARCH RESULT resultCode=32 " +
               "message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=1.234 referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" entriesReturned=1 " +
               "unindexed=true " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\"",
         ts() + " SEARCH RESULT instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "base=\"ou=People,dc=example,dc=com\" scope=0 " +
               "filter=\"(objectClass=*)\" attrs=\"ALL\" " +
               "message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" entriesReturned=1 " +
               "unindexed=true " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\"",
    };

    String[] longFilterLines = {
         ts() + " SEARCH REQUEST product=\"Identity Data Store\" " +
                 "instanceName=\"server.example.com:389\" threadID=7 conn=1 " +
                 "op=2 msgID=3 requesterIP=\"1.2.3.4\" " +
                 "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
                 "base=\"dc=example,dc=com\" scope=2 filter=" +
                 "\"(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|" +
                 "(|(|(|(|(cn=1095705)(cn=2397951))(cn=2397969))(cn=2397972))" +
                 "(cn=2453431))(cn=2643012))(cn=2643013))(cn=2643017))" +
                 "(cn=2678821))(cn=2705425))(cn=2705466))(cn=2707812))" +
                 "(cn=2714388))(cn=2714389))(cn=2714407))(cn=2770027))" +
                 "(cn=9023506))(cn=9023508))(cn=9066915))(cn=1095568))" +
                 "(cn=1675881))(cn=1893107))(cn=2031591))(cn=2397970))" +
                 "(cn=2459519))(cn=2595208))(cn=2609058))(cn=2643015))" +
                 "(cn=2643018))(cn=2648574))(cn=1742617))(cn=2685169))" +
                 "(cn=891530))\" attrs=\"givenName,sn\""
    };

    dataFile1 = createTempFile(lines);
    dataFile2 = createTempFile(lines);
    longFilterFile = createTempFile(longFilterLines);

    compressedFile = createTempFile();
    final PrintStream ps = new PrintStream(new GZIPOutputStream(
         new FileOutputStream(compressedFile)));
    for (final String s : lines)
    {
      ps.println(s);
    }
    ps.close();
  }



  /**
   * Provides general test coverage for the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void provideGeneralTestCoverage()
         throws Exception
  {
    final SummarizeAccessLog tool = new SummarizeAccessLog(null, null);
    assertNotNull(tool.getExampleUsages());

    assertTrue(tool.supportsInteractiveMode());
    assertTrue(tool.defaultsToInteractiveMode());
  }



  /**
   * Provides test coverage for the summarize-access-log tool with a single
   * file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleFile()
         throws Exception
  {
    String[] args =
    {
      dataFile1.getAbsolutePath()
    };

    ResultCode rc = SummarizeAccessLog.main(args, null, null);
    assertEquals(rc, ResultCode.SUCCESS);
  }


  /**
   * Provides test coverage for the summarize-access-log tool with a single
   * file with a very long filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLargeFilter()
          throws Exception
  {
    long startTime = System.currentTimeMillis();
    String[] args =
    {
       longFilterFile.getAbsolutePath()
    };
    ResultCode rc = SummarizeAccessLog.main(args, null, null);
    long endTime = System.currentTimeMillis();
    assertEquals(rc, ResultCode.SUCCESS);
    assertTrue(endTime - startTime < 5000);
  }



  /**
   * Provides test coverage for the summarize-access-log tool with multiple
   * files.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleFiles()
         throws Exception
  {
    String[] args =
    {
      dataFile1.getAbsolutePath(),
      dataFile2.getAbsolutePath()
    };

    ResultCode rc = SummarizeAccessLog.main(args, null, null);
    assertEquals(rc, ResultCode.SUCCESS);
  }



  /**
   * Provides test coverage for the summarize-access-log tool with a compressed
   * file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompressedFile()
         throws Exception
  {
    String[] args =
    {
      "-c",
      compressedFile.getAbsolutePath()
    };

    ResultCode rc = SummarizeAccessLog.main(args, null, null);
    assertEquals(rc, ResultCode.SUCCESS);
  }



  /**
   * Provides test coverage for the summarize-access-log tool without any files.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoFiles()
         throws Exception
  {
    String[] args = {};

    ResultCode rc = SummarizeAccessLog.main(args, null, null);
    assertFalse(rc.equals(ResultCode.SUCCESS));
  }



  /**
   * Provides test coverage for the summarize-access-log tool with a file that
   * does not exist..
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoSuchFile()
         throws Exception
  {
    String[] args =
    {
      dataFile1.getAbsolutePath() + ".missing"
    };

    ResultCode rc = SummarizeAccessLog.main(args, null, null);
    assertFalse(rc.equals(ResultCode.SUCCESS));
  }



  /**
   * Provides test coverage for the {@code getExampleUsages} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetExampleUsages()
         throws Exception
  {
    SummarizeAccessLog tool = new SummarizeAccessLog(null, null);

    assertNotNull(tool.getExampleUsages());
    assertFalse(tool.getExampleUsages().isEmpty());
  }



  /**
   * Generates a timestamp for use with the next log message.
   *
   * @return  A timestamp for use with the next log message.
   */
  private String ts()
  {
    Date d = new Date(lastTimestamp);
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    lastTimestamp += random.nextInt(10);

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    return f.format(d);
  }
}
