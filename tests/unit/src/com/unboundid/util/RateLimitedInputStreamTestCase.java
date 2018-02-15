/*
 * Copyright 2018 Ping Identity Corporation
 * All Rights Reserved.
 */
package com.unboundid.util;



import java.io.ByteArrayInputStream;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the rate-limited input stream.
 */
public final class RateLimitedInputStreamTestCase
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
    final ByteArrayInputStream wrappedStream =
         new ByteArrayInputStream(new byte[] { 0x00, 0x01, 0x02 });
    final RateLimitedInputStream inputStream =
         new RateLimitedInputStream(wrappedStream, 1);

    inputStream.available();

    assertTrue(inputStream.markSupported());
    inputStream.mark(3);
    inputStream.reset();

    final long startTime = System.currentTimeMillis();
    assertEquals(inputStream.read(), 0x00);

    final byte[] buffer = new byte[8192];
    assertEquals(inputStream.read(buffer), 2);
    assertEquals(buffer[0], (byte) 0x01);
    assertEquals(buffer[1], (byte) 0x02);

    assertEquals(inputStream.read(), -1);

    inputStream.close();

    final long elapsedTimeMillis = System.currentTimeMillis() - startTime;
    assertTrue(elapsedTimeMillis >= 2000L);
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
    final byte[] array = new byte[1_048_579];
    array[1] = (byte) 0x01;
    array[2] = (byte) 0x02;

    final ByteArrayInputStream wrappedStream = new ByteArrayInputStream(array);
    final RateLimitedInputStream inputStream =
         new RateLimitedInputStream(wrappedStream, 10_485_760);

    inputStream.available();

    assertTrue(inputStream.markSupported());
    inputStream.mark(3);
    inputStream.reset();

    final long startTime = System.currentTimeMillis();
    assertEquals(inputStream.read(), 0x00);

    assertEquals(inputStream.read(StaticUtils.NO_BYTES), 0);

    final byte[] buffer = new byte[8192];
    assertEquals(inputStream.read(buffer, 0, 2), 2);
    assertEquals(buffer[0], (byte) 0x01);
    assertEquals(buffer[1], (byte) 0x02);

    int totalBytesRead = 3;
    while (true)
    {
      final int bytesRead = inputStream.read(buffer);
      if (bytesRead < 0)
      {
        break;
      }

      totalBytesRead += bytesRead;
    }

    inputStream.close();

    final long elapsedTimeMillis = System.currentTimeMillis() - startTime;
    assertTrue(elapsedTimeMillis <= 10_000L);

    assertEquals(totalBytesRead, array.length);
  }
}
