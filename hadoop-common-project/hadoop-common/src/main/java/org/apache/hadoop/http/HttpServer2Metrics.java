/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.http;

import org.eclipse.jetty.server.handler.StatisticsHandler;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.metrics2.MetricsSystem;
import org.apache.hadoop.metrics2.annotation.Metric;
import org.apache.hadoop.metrics2.annotation.Metrics;
import org.apache.hadoop.metrics2.lib.DefaultMetricsSystem;

/**
 * This class collects all the metrics of Jetty's StatisticsHandler
 * and expose them as Hadoop Metrics.
 */
@InterfaceAudience.Private
@InterfaceStability.Unstable
@Metrics(name="HttpServer2", about="HttpServer2 metrics", context="http")
public class HttpServer2Metrics {

  private final StatisticsHandler handler;
  private final int port;

  @Metric("number of handled requests")
  public int handled() {
    return handler.getHandleTotal();
  }
  @Metric("number of handles currently active")
  public int handleActive() {
    return handler.getHandleActive();
  }
  @Metric("maximum number of active handles")
  public int handleActiveMax() {
    return handler.getHandleActiveMax();
  }
  @Metric("maximum time spend in handling (in ns)")
  public long handledTimeMax() {
    return handler.getHandleTimeMax();
  }
  @Metric("mean time spent in handling (in ns)")
  public double handledTimeMean() {
    return handler.getHandleTimeMean();
  }
  @Metric("standard deviation for handling (in ns)")
  public double handledTimeStdDev() {
    return handler.getHandleTimeStdDev();
  }
  @Metric("total time spent in handling (in ns)")
  public long handledTimeTotal() {
    return handler.getRequestTimeTotal();
  }
  @Metric("total number of failures in handling")
  public long handleFailed() {
    return handler.getHandlingFailures();
  }
  @Metric("number of requests")
  public int requests() {
    return handler.getRequestTotal();
  }
  @Metric("number of requests currently active")
  public int requestsActive() {
    return handler.getRequestsActive();
  }
  @Metric("maximum number of active requests")
  public int requestsActiveMax() {
    return handler.getRequestsActiveMax();
  }
  @Metric("maximum time spend handling requests (in ms)")
  public long requestTimeMax() {
    return handler.getRequestTimeMax();
  }
  @Metric("mean time spent handling requests (in ms)")
  public double requestTimeMean() {
    return handler.getRequestTimeMean();
  }
  @Metric("standard deviation for request handling (in ms)")
  public double requestTimeStdDev() {
    return handler.getRequestTimeStdDev();
  }
  @Metric("total time spend in all request handling (in ms)")
  public long requestTimeTotal() {
    return handler.getRequestTimeTotal();
  }
  @Metric("total number of failed requests")
  public long requestFailed() {
    return handler.getFailures();
  }
  @Metric("number of requests with 1xx response status")
  public int responses1xx() {
    return handler.getResponses1xx();
  }
  @Metric("number of requests with 2xx response status")
  public int responses2xx() {
    return handler.getResponses2xx();
  }
  @Metric("number of requests with 3xx response status")
  public int responses3xx() {
    return handler.getResponses3xx();
  }
  @Metric("number of requests with 4xx response status")
  public int responses4xx() {
    return handler.getResponses4xx();
  }
  @Metric("number of requests with 5xx response status")
  public int responses5xx() {
    return handler.getResponses5xx();
  }
  @Metric("total number of bytes across all responses")
  public long responsesBytesTotal() {
    return handler.getBytesWritten();
  }
  @Metric("total number of bytes across all requests")
  public long requestsBytesTotal() {
    return handler.getBytesRead();
  }
  @Metric("time in milliseconds stats have been collected for")
  public long statsOnMs() {
    return handler.getStatisticsDuration().toMillis();
  }

  HttpServer2Metrics(StatisticsHandler handler, int port) {
    this.handler = handler;
    this.port = port;
  }

  static HttpServer2Metrics create(StatisticsHandler handler, int port) {
    final MetricsSystem ms = DefaultMetricsSystem.instance();
    final HttpServer2Metrics metrics = new HttpServer2Metrics(handler, port);
    // Remove the old metrics from metrics system to avoid duplicate error
    // when HttpServer2 is started twice.
    metrics.remove();
    // Add port number to the suffix to allow multiple instances in a host.
    return ms.register("HttpServer2-" + port, "HttpServer2 metrics", metrics);
  }

  void remove() {
    DefaultMetricsSystem.removeSourceName("HttpServer2-" + port);
  }
}
