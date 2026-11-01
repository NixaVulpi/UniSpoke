package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kardianos/service"
)

const (
	serviceName        = "unispoke"
	serviceDisplayName = "UniSpoke"
	serviceDescription = "UniSpoke SSL VPN client and proxy"
	serviceFlag        = "service"
	serviceActions     = "install|uninstall|start|stop|restart|status"
)

// serviceProgram 实现 service.Interface：Start 异步启动主程序，Stop 触发清理并等待收尾。
type serviceProgram struct {
	opts options
	logf func(string, ...any)
	errf func(string, ...any)
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

func (p *serviceProgram) Start(s service.Service) error {
	if p.logf == nil {
		p.logf = func(string, ...any) {}
	}
	if p.errf == nil {
		p.errf = p.logf
	}
	go func() {
		defer close(p.done)
		if err := runApplication(p.opts, p.stop, p.logf); err != nil {
			p.errf("fatal: %v", err)
			// 启动失败直接退出，让服务管理器按恢复策略重启。
			os.Exit(1)
		}
	}()
	return nil
}

func (p *serviceProgram) Stop(s service.Service) error {
	p.once.Do(func() { close(p.stop) })
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
	}
	return nil
}

// serviceConfig 生成服务定义。Arguments 即固化的启动参数，安装时写入系统服务。
func serviceConfig(args []string) *service.Config {
	cfg := &service.Config{
		Name:        serviceName,
		DisplayName: serviceDisplayName,
		Description: serviceDescription,
		Arguments:   args,
		Option: service.KeyValue{
			"OnFailure":              "restart",
			"OnFailureDelayDuration": "5s",
		},
	}
	if exe, err := os.Executable(); err == nil {
		cfg.WorkingDirectory = filepath.Dir(exe)
	}
	return cfg
}

// serviceArguments 去掉 -service 控制参数，其余参数原样固化进服务定义。
func serviceArguments(args []string) []string {
	short := "-" + serviceFlag
	long := "--" + serviceFlag
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == short || a == long {
			i++
			continue
		}
		if strings.HasPrefix(a, short+"=") || strings.HasPrefix(a, long+"=") {
			continue
		}
		out = append(out, a)
	}
	return out
}

// absoluteCaPath 把 -ca 的相对路径改成绝对路径；服务的工作目录不是程序目录。
func absoluteCaPath(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i < len(out); i++ {
		a := out[i]
		switch {
		case a == "-ca" || a == "--ca":
			if i+1 < len(out) {
				out[i+1] = absPath(out[i+1])
				i++
			}
		case strings.HasPrefix(a, "-ca="):
			out[i] = "-ca=" + absPath(strings.TrimPrefix(a, "-ca="))
		case strings.HasPrefix(a, "--ca="):
			out[i] = "--ca=" + absPath(strings.TrimPrefix(a, "--ca="))
		}
	}
	return out
}

func absPath(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

func runServiceAction(opts options) error {
	action := strings.ToLower(opts.service)
	switch action {
	case "install", "uninstall", "start", "stop", "restart", "status":
	default:
		return fmt.Errorf("unknown -service action %q (%s)", opts.service, serviceActions)
	}

	args := serviceArguments(os.Args[1:])
	if action == "install" {
		if opts.gateway == "" || opts.user == "" || opts.password == "" {
			return errors.New("service install requires -gateway, -user and -password")
		}
		args = absoluteCaPath(args)
		// 服务不继承用户环境变量，把环境变量里的口令同样固化进服务参数。
		if opts.passwordEnv {
			args = append(args, "-password", opts.password)
		}
	}

	s, err := service.New(&serviceProgram{}, serviceConfig(args))
	if err != nil {
		return err
	}

	if action == "status" {
		st, err := s.Status()
		if err != nil {
			return err
		}
		fmt.Printf("%s: %s\n", serviceDisplayName, statusString(st))
		return nil
	}

	if action == "uninstall" {
		// 运行中的服务先停止，否则 Windows 只是标记删除、systemd 只是移除 unit。
		_ = s.Stop()
		return s.Uninstall()
	}

	if err := service.Control(s, action); err != nil {
		return err
	}
	if action == "install" {
		fmt.Printf("service %q installed with %d argument(s)\n", serviceName, len(args))
		fmt.Printf("use \"%s -service start\" to start it\n", progName)
	}
	return nil
}

func statusString(st service.Status) string {
	switch st {
	case service.StatusRunning:
		return "running"
	case service.StatusStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

func teeInfo(base func(string, ...any), l service.Logger) func(string, ...any) {
	return func(format string, args ...any) {
		base(format, args...)
		_ = l.Infof(format, args...)
	}
}

func teeError(base func(string, ...any), l service.Logger) func(string, ...any) {
	return func(format string, args ...any) {
		base(format, args...)
		_ = l.Errorf(format, args...)
	}
}
