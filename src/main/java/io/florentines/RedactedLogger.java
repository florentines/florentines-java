/*
 * Copyright 2022 Neil Madden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package io.florentines;

import java.security.Key;
import java.util.Arrays;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;

/**
 * An slf4j-compatible logger that redacts certain types of arguments to prevent them being leaked in log files.
 */
final class RedactedLogger implements Logger {
    private final Logger realLogger;

    private RedactedLogger(Logger realLogger) {
        this.realLogger = Objects.requireNonNull(realLogger);
    }

    static RedactedLogger getLogger(Class<?> forClass) {
        return new RedactedLogger(LoggerFactory.getLogger(forClass));
    }

    @Override
    public String getName() {
        return realLogger.getName();
    }

    @Override
    public boolean isTraceEnabled() {
        return realLogger.isTraceEnabled();
    }

    @Override
    public void trace(String s) {
        realLogger.trace(s);
    }

    @Override
    public void trace(String s, Object o) {
        if (isTraceEnabled()) {
            realLogger.trace(s, redact(o));
        }
    }

    @Override
    public void trace(String s, Object o, Object o1) {
        if (isTraceEnabled()) {
            realLogger.trace(s, redact(o), redact(o1));
        }
    }

    @Override
    public void trace(String s, Object... objects) {
        if (isTraceEnabled()) {
            realLogger.trace(s, redactAll(objects));
        }
    }

    @Override
    public void trace(String s, Throwable throwable) {
        realLogger.trace(s, throwable);
    }

    @Override
    public boolean isTraceEnabled(Marker marker) {
        return realLogger.isTraceEnabled(marker);
    }

    @Override
    public void trace(Marker marker, String s) {
        realLogger.trace(marker, s);
    }

    @Override
    public void trace(Marker marker, String s, Object o) {
        if (isTraceEnabled(marker)) {
            realLogger.trace(marker, s, redact(o));
        }
    }

    @Override
    public void trace(Marker marker, String s, Object o, Object o1) {
        if (isTraceEnabled(marker)) {
            realLogger.trace(marker, s, redact(o), redact(o1));
        }
    }

    @Override
    public void trace(Marker marker, String s, Object... objects) {
        if (isTraceEnabled(marker)) {
            realLogger.trace(marker, s, redactAll(objects));
        }
    }

    @Override
    public void trace(Marker marker, String s, Throwable throwable) {
        realLogger.trace(marker, s, throwable);
    }

    @Override
    public boolean isDebugEnabled() {
        return realLogger.isDebugEnabled();
    }

    @Override
    public void debug(String s) {
        realLogger.debug(s);
    }

    @Override
    public void debug(String s, Object o) {
        if (isDebugEnabled()) {
            realLogger.debug(s, redact(o));
        }
    }

    @Override
    public void debug(String s, Object o, Object o1) {
        if (isDebugEnabled()) {
            realLogger.debug(s, redact(o), redact(o1));
        }
    }

    @Override
    public void debug(String s, Object... objects) {
        if (isDebugEnabled()) {
            realLogger.debug(s, redactAll(objects));
        }
    }

    @Override
    public void debug(String s, Throwable throwable) {
        realLogger.debug(s, throwable);
    }

    @Override
    public boolean isDebugEnabled(Marker marker) {
        return realLogger.isDebugEnabled(marker);
    }

    @Override
    public void debug(Marker marker, String s) {
        realLogger.debug(marker, s);
    }

    @Override
    public void debug(Marker marker, String s, Object o) {
        if (isDebugEnabled(marker)) {
            realLogger.debug(marker, s, redact(o));
        }
    }

    @Override
    public void debug(Marker marker, String s, Object o, Object o1) {
        if (isDebugEnabled(marker)) {
            realLogger.debug(marker, s, redact(o), redact(o1));
        }
    }

    @Override
    public void debug(Marker marker, String s, Object... objects) {
        if (isDebugEnabled(marker)) {
            realLogger.debug(marker, s, redactAll(objects));
        }
    }

    @Override
    public void debug(Marker marker, String s, Throwable throwable) {
        realLogger.debug(marker, s, throwable);
    }

    @Override
    public boolean isInfoEnabled() {
        return realLogger.isInfoEnabled();
    }

    @Override
    public void info(String s) {
        realLogger.info(s);
    }

    @Override
    public void info(String s, Object o) {
        if (isInfoEnabled()) {
            realLogger.info(s, redact(o));
        }
    }

    @Override
    public void info(String s, Object o, Object o1) {
        if (isInfoEnabled()) {
            realLogger.info(s, redact(o), redact(o1));
        }
    }

    @Override
    public void info(String s, Object... objects) {
        if (isInfoEnabled()) {
            realLogger.info(s, redactAll(objects));
        }
    }

    @Override
    public void info(String s, Throwable throwable) {
        realLogger.info(s, throwable);
    }

    @Override
    public boolean isInfoEnabled(Marker marker) {
        return realLogger.isInfoEnabled(marker);
    }

    @Override
    public void info(Marker marker, String s) {
        realLogger.info(marker, s);
    }

    @Override
    public void info(Marker marker, String s, Object o) {
        if (isInfoEnabled(marker)) {
            realLogger.info(marker, s, redact(o));
        }
    }

    @Override
    public void info(Marker marker, String s, Object o, Object o1) {
        if (isInfoEnabled(marker)) {
            realLogger.info(marker, s, redact(o), redact(o1));
        }
    }

    @Override
    public void info(Marker marker, String s, Object... objects) {
        if (isInfoEnabled(marker)) {
            realLogger.info(marker, s, redactAll(objects));
        }
    }

    @Override
    public void info(Marker marker, String s, Throwable throwable) {
        realLogger.info(marker, s, throwable);
    }

    @Override
    public boolean isWarnEnabled() {
        return realLogger.isWarnEnabled();
    }

    @Override
    public void warn(String s) {
        realLogger.warn(s);
    }

    @Override
    public void warn(String s, Object o) {
        if (isWarnEnabled()) {
            realLogger.warn(s, redact(o));
        }
    }

    @Override
    public void warn(String s, Object... objects) {
        if (isWarnEnabled()) {
            realLogger.warn(s, redactAll(objects));
        }
    }

    @Override
    public void warn(String s, Object o, Object o1) {
        if (isWarnEnabled()) {
            realLogger.warn(s, redact(o), redact(o1));
        }
    }

    @Override
    public void warn(String s, Throwable throwable) {
        realLogger.warn(s, throwable);
    }

    @Override
    public boolean isWarnEnabled(Marker marker) {
        return realLogger.isWarnEnabled(marker);
    }

    @Override
    public void warn(Marker marker, String s) {
        realLogger.warn(marker, s);
    }

    @Override
    public void warn(Marker marker, String s, Object o) {
        if (isWarnEnabled(marker)) {
            realLogger.warn(marker, s, redact(o));
        }
    }

    @Override
    public void warn(Marker marker, String s, Object o, Object o1) {
        if (isWarnEnabled(marker)) {
            realLogger.warn(marker, s, redact(o), redact(o1));
        }
    }

    @Override
    public void warn(Marker marker, String s, Object... objects) {
        if (isWarnEnabled(marker)) {
            realLogger.warn(marker, s, redactAll(objects));
        }
    }

    @Override
    public void warn(Marker marker, String s, Throwable throwable) {
        realLogger.warn(marker, s, throwable);
    }

    @Override
    public boolean isErrorEnabled() {
        return realLogger.isErrorEnabled();
    }

    @Override
    public void error(String s) {
        realLogger.error(s);
    }

    @Override
    public void error(String s, Object o) {
        if (isErrorEnabled()) {
            realLogger.error(s, redact(o));
        }
    }

    @Override
    public void error(String s, Object o, Object o1) {
        if (isErrorEnabled()) {
            realLogger.error(s, redact(o), redact(o1));
        }
    }

    @Override
    public void error(String s, Object... objects) {
        if (isErrorEnabled()) {
            realLogger.error(s, redactAll(objects));
        }
    }

    @Override
    public void error(String s, Throwable throwable) {
        realLogger.error(s, throwable);
    }

    @Override
    public boolean isErrorEnabled(Marker marker) {
        return realLogger.isErrorEnabled(marker);
    }

    @Override
    public void error(Marker marker, String s) {
        realLogger.error(marker, s);
    }

    @Override
    public void error(Marker marker, String s, Object o) {
        if (isErrorEnabled(marker)) {
            realLogger.error(marker, s, redact(o));
        }
    }

    @Override
    public void error(Marker marker, String s, Object o, Object o1) {
        if (isErrorEnabled(marker)) {
            realLogger.error(marker, s, redact(o), redact(o1));
        }
    }

    @Override
    public void error(Marker marker, String s, Object... objects) {
        if (isErrorEnabled(marker)) {
            realLogger.error(marker, s, redactAll(objects));
        }
    }

    @Override
    public void error(Marker marker, String s, Throwable throwable) {
        realLogger.error(marker, s, throwable);
    }

    private static Object redact(Object arg) {
        if (arg instanceof byte[]) {
            return maskForLog((byte[]) arg);
        } else if (arg instanceof Key) {
            return maskForLog(((Key) arg).getEncoded());
        } else {
            return arg;
        }
    }

    private static Object[] redactAll(Object[] args) {
        return Arrays.stream(args).map(RedactedLogger::redact).toArray();
    }

    private static String maskForLog(byte[] secret) {
        return secret == null
                ? "null"
                : secret.length < 16
                ? "<redacted>"
                : Utils.hex(Arrays.copyOf(secret, 3)) + "..." +
                Utils.hex(Arrays.copyOfRange(secret, secret.length-3, secret.length));
    }
}
