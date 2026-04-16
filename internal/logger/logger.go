package logger

import (
    "fmt"
    "io"
    "log"
    "os"
    "time"
)

type Level int

const (
    INFO Level = iota
    WARNING
    ERROR
)

type Logger struct {
    *log.Logger
    level  Level
    output io.Writer
}

func NewLogger(logFile string) (*Logger, error) {
    var writer io.Writer = os.Stderr
    
    if logFile != "" {
        file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
            return nil, fmt.Errorf("failed to open log file: %w", err)
        }
        writer = file
    }
    
    return &Logger{
        Logger: log.New(writer, "", 0),
        level:  INFO,
        output: writer,
    }, nil
}

func (l *Logger) log(level Level, format string, v ...interface{}) {
    if level < l.level {
        return
    }
    
    levelStr := map[Level]string{
        INFO:    "INFO",
        WARNING: "WARNING",
        ERROR:   "ERROR",
    }[level]
    
    timestamp := time.Now().Format("2006-01-02T15:04:05.000Z07:00")
    msg := fmt.Sprintf(format, v...)
    l.Logger.Printf("%s [%s] %s", timestamp, levelStr, msg)
}

func (l *Logger) Info(format string, v ...interface{}) {
    l.log(INFO, format, v...)
}

func (l *Logger) Warning(format string, v ...interface{}) {
    l.log(WARNING, format, v...)
}

func (l *Logger) Error(format string, v ...interface{}) {
    l.log(ERROR, format, v...)
}

func (l *Logger) Close() error {
    if f, ok := l.output.(*os.File); ok && f != os.Stderr && f != os.Stdout {
        return f.Close()
    }
    return nil
}