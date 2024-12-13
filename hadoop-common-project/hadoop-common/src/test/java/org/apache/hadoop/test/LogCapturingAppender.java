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
package org.apache.hadoop.test;

import java.io.Serializable;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginAttribute;
import org.apache.logging.log4j.core.config.plugins.PluginElement;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;
import org.apache.logging.log4j.core.layout.PatternLayout;

/**
 * Used to verify that certain exceptions or messages are present in log output.
 */
@Plugin(name="CapturingAppender", category="Core", elementType="appender", printObject=true)
public class LogCapturingAppender extends AbstractAppender {

  protected static final Map<String, Consumer<LogEvent>> eventConsumers =
    new ConcurrentHashMap<>();

  protected LogCapturingAppender(String name, Filter filter, Layout<? extends Serializable> layout,
            boolean ignoreExceptions, Property[] properties) {
    super(name, filter, layout, ignoreExceptions, properties);
  }

  @Override
  public void append(LogEvent event) {
    eventConsumers.getOrDefault(
        event.getLoggerName(),
        e -> {})
      .accept(event);
  }

  public static void consumeEvents(String loggerName, Consumer<LogEvent> consumer) {
    eventConsumers.put(loggerName, consumer);
  }

  public static void collectEvents(String loggerName, Collection<LogEvent> collection) {
    consumeEvents(loggerName, collection::add);
  }

  public static void consumeMessages(String loggerName, Consumer<String> consumer) {
    eventConsumers.put(loggerName,
      e -> consumer.accept(e.getMessage().getFormattedMessage()));
  }

  public static void collectMessages(String loggerName, Collection<String> collection) {
    consumeMessages(loggerName, collection::add);
  }

  public static void concatMessages(String loggerName, StringBuffer buf) {
    consumeMessages(loggerName, buf::append);
  }

  public static void stop(String loggerName) {
    eventConsumers.remove(loggerName);
  }

  @PluginFactory
  public static LogCapturingAppender create(
          @PluginAttribute("name") String name,
          @PluginElement("Layout") Layout<? extends Serializable> layout,
          @PluginElement("Filter") Filter filter) {
    return new LogCapturingAppender(
      name,
      filter,
      layout == null ? PatternLayout.createDefaultLayout() : layout,
      true,
      new Property[] {});
  }
}
