/*
 * Copyright 2018 Ping Identity Corporation
 * All Rights Reserved.
 */
package com.unboundid.util;



import java.io.ByteArrayOutputStream;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the rate-limited output stream.
 */
public final class RateLimitedOutputStreamTestCase
       extends LDAPSDKTestCase
{
  /**
   * Test the output stream with a tiny limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithTinyLimit()
         throws Exception
  {
    final ByteArrayOutputStream wrappedStream = new ByteArrayOutputStream();
    final RateLimitedOutputStream outputStream =
         new RateLimitedOutputStream(wrappedStream, 1, false);

    final long startTime = System.currentTimeMillis();
    outputStream.write(0x00);

    outputStream.write(StaticUtils.NO_BYTES);

    final byte[] array = { 0x01, 0x02 };
    outputStream.write(array);

    outputStream.flush();

    outputStream.close();

    final long elapsedTimeMillis = System.currentTimeMillis() - startTime;
    assertTrue(elapsedTimeMillis >= 2000L);

    assertEquals(wrappedStream.toByteArray(),
         new byte[] { 0x00, 0x01, 0x02 });
  }



  /**
   * Test the output stream with a big limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithBigLimit()
         throws Exception
  {
    final ByteArrayOutputStream wrappedStream = new ByteArrayOutputStream();
    final RateLimitedOutputStream outputStream =
         new RateLimitedOutputStream(wrappedStream, 10_485_760, true);

    final long startTime = System.currentTimeMillis();
    outputStream.write(0x00);

    outputStream.write(StaticUtils.NO_BYTES);

    outputStream.write(new byte[] { 0x01, 0x02});

    final byte[] array = new byte[1_048_576];
    outputStream.write(array);

    outputStream.flush();

    outputStream.close();

    final long elapsedTimeMillis = System.currentTimeMillis() - startTime;
    assertTrue(elapsedTimeMillis <= 10_000L);

    final byte[] bytesWritten = wrappedStream.toByteArray();
    assertEquals(bytesWritten.length, array.length + 3);
  }
}
