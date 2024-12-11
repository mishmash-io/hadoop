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

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.AppenderRef;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.layout.PatternLayout;

/**
 * Used to verify that certain exceptions or messages are present in log output.
 */
public class LogVerificationAppender extends AbstractAppender {
  private static final String NAME = "LogVerificationAppender";

  private final List<LogEvent> log = new ArrayList<LogEvent>();

  protected LogVerificationAppender(PatternLayout layout) {
    super(NAME, null, layout, true, Property.EMPTY_ARRAY);
  }

  @Override
  public void append(final LogEvent loggingEvent) {
    log.add(loggingEvent);
  }

  /**
   * Get a list of log events since last 
   * @return
   */
  public List<LogEvent> getLog() {
    return new ArrayList<LogEvent>(log);
  }

  /**
   * Returns all captured messages concatenated into a String.
   *
   * @return the text log
   */
  public String getAllAsText() {
    return log.stream().map(e -> e.getMessage().getFormattedMessage())
        .collect(Collectors.joining());
  }

  /**
   * Clears the log captured so far.
   *
   * Ideally call before each test, as the log may contain
   * messages from a previous test.
   */
  public void clearLog() {
    log.clear();
  }

  public int countExceptionsWithMessage(final String text) {
    int count = 0;
    for (LogEvent e: getLog()) {
      Throwable t = e.getThrown();
      if (t != null) {
        String m = t.getMessage();
        if (m.contains(text)) {
          count++;
        }
      }
    }
    return count;
  }

  public int countLinesWithMessage(final String text) {
    int count = 0;
    for (LogEvent e: getLog()) {
      String msg = e.getMessage().getFormattedMessage();
      if (msg != null && msg.contains(text)) {
        count++;
      }
    }
    return count;
  }

  public int countLinesWithMessage(final Pattern pattern) {
    int count = 0;
    for (LogEvent e: getLog()) {
      String msg = e.getMessage().getFormattedMessage();
      if (msg != null && pattern.matcher(msg).matches()) {
        count++;
      }
    }
    return count;
  }

  /**
   * Configures log4j2 to include a LogVerificationAppender,
   * if one is not already configured into the system.
   *
   * NOTE: call {@link #addToLogger(String, String)} to directly
   * instantiate an Appender AND install it into a Logger.
   *
   * @return the newly added Appender or the existing one
   */
  public static LogVerificationAppender getOrInstall() {
    LoggerContext ctx = LoggerContext.getContext(true);
    Configuration conf = ctx.getConfiguration();
    if (conf.getAppender(NAME) != null) {
      return (LogVerificationAppender) conf.getAppender(NAME);
    }
    PatternLayout layout = PatternLayout.createDefaultLayout(conf);
    LogVerificationAppender appender = new LogVerificationAppender(layout);
    appender.start();
    conf.addAppender(appender);
    return appender;
  }

  /**
   * Configures a Logger (possibly identifed by loggerName) to use a LogVerificationAppender.
   *
   * Use this method to obtain and attach the LogVerificationAppender to a Logger.
   *
   * If a Logger by the given name does not exist yet - it will be configured with a
   * level of newLoggerLevel. If loggerName is given as null - then use the root logger.
   *
   * If LogVerificationAppender has not yet been configured into log4j2 - it too will be
   * automatically added.
   *
   * @param loggerName - the name of the Logger to 'tap' or the root logger when null
   * @param newLoggerLevel - the level to set should a new Logger be created
   */
  public static LogVerificationAppender addToLogger(
      final String loggerName, final String newLoggerLevel) {
    LoggerContext ctx = LoggerContext.getContext(true);
    Logger logger;
    if (loggerName == null) {
      logger = ctx.getRootLogger();
    } else {
      logger = ctx.getLogger(loggerName);
    }
    LogVerificationAppender appender = getOrInstall();
    if (logger != null) {
      if (logger.get().getAppenders().containsKey(NAME)) {
        return appender;
      }
      logger.addAppender(appender);
    } else {
      Configuration conf = ctx.getConfiguration();
      AppenderRef[] refs = new AppenderRef[] {
            AppenderRef.createAppenderRef("logVerificationAppender", null, null)
      };
      LoggerConfig loggerConf = LoggerConfig.createLogger(
            false, Level.getLevel(newLoggerLevel), loggerName, "true",
            refs, null, conf, null);
      loggerConf.addAppender(appender, null, null);
      conf.addLogger(loggerName, loggerConf);
    }
    ctx.updateLoggers();
    return appender;
  }
}
