package log

import (
	"context"
	"io"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service/filemanager"
)

var _ Factory = (*defaultFactory)(nil)

const asyncLogTaskBufferSize = 2048

type asyncLogTask struct {
	ctx   context.Context
	level Level
	tag   string
	args  []any
	time  time.Time
}

type defaultFactory struct {
	ctx               context.Context
	formatter         Formatter
	platformFormatter Formatter
	rawWriter         io.Writer
	writer            io.Writer
	asyncWriter       *asyncWriter
	file              *os.File
	filePath          string
	platformWriter    PlatformWriter
	needObservable    bool
	level             Level
	subscriber        *observable.Subscriber[Entry]
	observer          *observable.Observer[Entry]
	logQueue          chan asyncLogTask
	logDone           chan struct{}
	logClosed         atomic.Bool
	logDropped        atomic.Uint64
}

func NewDefaultFactory(
	ctx context.Context,
	formatter Formatter,
	writer io.Writer,
	filePath string,
	platformWriter PlatformWriter,
	needObservable bool,
) ObservableFactory {
	factory := &defaultFactory{
		ctx:       ctx,
		formatter: formatter,
		platformFormatter: Formatter{
			BaseTime:         formatter.BaseTime,
			DisableLineBreak: true,
		},
		writer:         writer,
		filePath:       filePath,
		platformWriter: platformWriter,
		needObservable: needObservable,
		level:          LevelTrace,
		subscriber:     observable.NewSubscriber[Entry](128),
		logQueue:       make(chan asyncLogTask, asyncLogTaskBufferSize),
		logDone:        make(chan struct{}),
	}
	/*if platformWriter != nil {
		factory.platformFormatter.DisableColors = platformWriter.DisableColors()
	}*/
	if needObservable {
		factory.observer = observable.NewObserver[Entry](factory.subscriber, 64)
	}
	factory.setWriter(writer)
	go factory.processLogTasks()
	return factory
}

func (f *defaultFactory) Start() error {
	if f.filePath != "" {
		logFile, err := filemanager.OpenFile(f.ctx, f.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		f.file = logFile
		f.setWriter(logFile)
	}
	return nil
}

func (f *defaultFactory) Close() error {
	if f.logClosed.CompareAndSwap(false, true) {
		close(f.logDone)
	}
	return common.Close(
		common.PtrOrNil(f.asyncWriter),
		common.PtrOrNil(f.file),
		f.subscriber,
	)
}

func (f *defaultFactory) setWriter(writer io.Writer) {
	if f.asyncWriter != nil {
		_ = f.asyncWriter.Close()
	}
	if writer == nil {
		f.rawWriter = nil
		f.writer = nil
		f.asyncWriter = nil
		return
	}
	f.rawWriter = writer
	f.asyncWriter = newAsyncWriter(writer)
	f.writer = f.asyncWriter
}

func (f *defaultFactory) Level() Level {
	return f.level
}

func (f *defaultFactory) SetLevel(level Level) {
	f.level = level
}

func (f *defaultFactory) Logger() ContextLogger {
	return f.NewLogger("")
}

func (f *defaultFactory) NewLogger(tag string) ContextLogger {
	return &observableLogger{f, tag}
}

func (f *defaultFactory) Subscribe() (subscription observable.Subscription[Entry], done <-chan struct{}, err error) {
	return f.observer.Subscribe()
}

func (f *defaultFactory) UnSubscribe(sub observable.Subscription[Entry]) {
	f.observer.UnSubscribe(sub)
}

func (f *defaultFactory) enqueueLogTask(task asyncLogTask) {
	select {
	case <-f.logDone:
		return
	default:
	}
	select {
	case f.logQueue <- task:
	default:
		f.logDropped.Add(1)
	}
}

func (f *defaultFactory) processLogTasks() {
	for {
		select {
		case <-f.logDone:
			f.flushLogTasks()
			return
		case task := <-f.logQueue:
			f.writeLogTask(task)
		}
	}
}

func (f *defaultFactory) flushLogTasks() {
	for {
		select {
		case task := <-f.logQueue:
			f.writeLogTask(task)
		default:
			f.writeDroppedLogTasks()
			return
		}
	}
}

func (f *defaultFactory) writeLogTask(task asyncLogTask) {
	f.writeDroppedLogTasks()
	content := F.ToString(task.args...)
	if f.needObservable {
		message, messageSimple := f.formatter.FormatWithSimple(task.ctx, task.level, task.tag, content, task.time)
		if task.level == LevelPanic {
			f.writeSync(message)
			panic(message)
		}
		if task.level == LevelFatal {
			f.writeSync(message)
			os.Exit(1)
		}
		f.writeAsync(message)
		f.subscriber.Emit(Entry{task.level, messageSimple})
	} else {
		message := f.formatter.Format(task.ctx, task.level, task.tag, content, task.time)
		if task.level == LevelPanic {
			f.writeSync(message)
			panic(message)
		}
		if task.level == LevelFatal {
			f.writeSync(message)
			os.Exit(1)
		}
		f.writeAsync(message)
	}
	if f.platformWriter != nil {
		f.platformWriter.WriteMessage(task.level, f.platformFormatter.Format(task.ctx, task.level, task.tag, content, task.time))
	}
}

func (f *defaultFactory) writeAsync(message string) {
	if f.writer != nil {
		f.writer.Write([]byte(message))
	}
}

func (f *defaultFactory) writeSync(message string) {
	if f.rawWriter != nil {
		f.rawWriter.Write([]byte(message))
	}
}

func (f *defaultFactory) writeDroppedLogTasks() {
	dropped := f.logDropped.Swap(0)
	if dropped == 0 {
		return
	}
	content := "dropped " + strconv.FormatUint(dropped, 10) + " log messages because the async log queue is full"
	message, messageSimple := f.formatter.FormatWithSimple(context.Background(), LevelWarn, "", content, time.Now())
	f.writer.Write([]byte(message))
	if f.needObservable {
		f.subscriber.Emit(Entry{LevelWarn, messageSimple})
	}
	if f.platformWriter != nil {
		f.platformWriter.WriteMessage(LevelWarn, f.platformFormatter.Format(context.Background(), LevelWarn, "", content, time.Now()))
	}
}

var _ ContextLogger = (*observableLogger)(nil)

type observableLogger struct {
	*defaultFactory
	tag string
}

func (l *observableLogger) Log(ctx context.Context, level Level, args []any) {
	level = OverrideLevelFromContext(level, ctx)
	if level > l.level {
		return
	}
	task := asyncLogTask{
		ctx:   ctx,
		level: level,
		tag:   l.tag,
		args:  append([]any(nil), args...),
		time:  time.Now(),
	}
	if level == LevelPanic || level == LevelFatal {
		l.writeLogTask(task)
		return
	}
	l.enqueueLogTask(task)
}

func (l *observableLogger) Trace(args ...any) {
	l.TraceContext(context.Background(), args...)
}

func (l *observableLogger) Debug(args ...any) {
	l.DebugContext(context.Background(), args...)
}

func (l *observableLogger) Info(args ...any) {
	l.InfoContext(context.Background(), args...)
}

func (l *observableLogger) Warn(args ...any) {
	l.WarnContext(context.Background(), args...)
}

func (l *observableLogger) Error(args ...any) {
	l.ErrorContext(context.Background(), args...)
}

func (l *observableLogger) Fatal(args ...any) {
	l.FatalContext(context.Background(), args...)
}

func (l *observableLogger) Panic(args ...any) {
	l.PanicContext(context.Background(), args...)
}

func (l *observableLogger) TraceContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelTrace, args)
}

func (l *observableLogger) DebugContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelDebug, args)
}

func (l *observableLogger) InfoContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelInfo, args)
}

func (l *observableLogger) WarnContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelWarn, args)
}

func (l *observableLogger) ErrorContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelError, args)
}

func (l *observableLogger) FatalContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelFatal, args)
}

func (l *observableLogger) PanicContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelPanic, args)
}
