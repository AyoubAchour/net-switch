package winplatform

import (
	"fmt"
	"path/filepath"
	"strings"

	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"golang.org/x/sys/windows"
)

func taskService() (*comObject, error) {
	s, err := comCreate("{0f87369f-a4e5-4cfc-bd3e-73e6154572dd}", &iidDispatch)
	if err != nil {
		return nil, err
	}
	if err := s.discard("Connect", 1); err != nil {
		s.release()
		return nil, err
	}
	return s, nil
}
func taskEnabled() (any, error) {
	return comThread(func() (any, error) {
		s, err := taskService()
		if err != nil {
			return nil, err
		}
		defer s.release()
		folder, err := s.object("GetFolder", 1, `\Net Switch`)
		if err != nil {
			if missingCOM(err) {
				return false, nil
			}
			return nil, err
		}
		defer folder.release()
		for _, name := range []string{"Server", "Sign-in"} {
			task, err := folder.object("GetTask", 1, name)
			if err != nil {
				if missingCOM(err) {
					return false, nil
				}
				return nil, err
			}
			v, err := task.call("Enabled", 2)
			task.release()
			if err != nil {
				return nil, err
			}
			enabled := v.vt == 11 && v.data != 0
			v.clear()
			if !enabled {
				return false, nil
			}
		}
		return true, nil
	})
}
func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&#38;", "<", "&#60;", ">", "&#62;", "\"", "&#34;", "'", "&#39;").Replace(s)
}
func taskXML(description, trigger, level, command, args, root, sid string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>%s</Description></RegistrationInfo>
  <Triggers>%s</Triggers>
  <Principals><Principal id="Person"><UserId>%s</UserId><LogonType>InteractiveToken</LogonType><RunLevel>%s</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>4</Priority>
  </Settings>
  <Actions Context="Person"><Exec><Command>%s</Command><Arguments>%s</Arguments><WorkingDirectory>%s</WorkingDirectory></Exec></Actions>
</Task>
`, xmlEscape(description), trigger, xmlEscape(sid), level, xmlEscape(command), xmlEscape(args), xmlEscape(root))
}
func setTasks(a map[string]any) error {
	_, err := comThread(func() (any, error) {
		s, err := taskService()
		if err != nil {
			return nil, err
		}
		defer s.release()
		root, err := s.object("GetFolder", 1, `\`)
		if err != nil {
			return nil, err
		}
		defer root.release()
		folder, err := root.object("GetFolder", 1, "Net Switch")
		if a["on"] != true {
			if err != nil {
				if missingCOM(err) {
					return nil, nil
				}
				return nil, err
			}
			defer folder.release()
			for _, name := range []string{"Server", "Sign-in"} {
				if err := folder.discard("DeleteTask", 1, name, 0); err != nil && !missingCOM(err) {
					return nil, err
				}
			}
			_ = root.discard("DeleteFolder", 1, "Net Switch", 0)
			return nil, nil
		}
		if err != nil {
			if !missingCOM(err) {
				return nil, err
			}
			folder, err = root.object("CreateFolder", 1, "Net Switch")
			if err != nil {
				return nil, err
			}
		}
		defer folder.release()
		exe := js.Text(a["executable"])
		dir := js.Text(a["root"])
		userDir := js.Text(a["userDir"])
		machineDir := js.Text(a["machineDir"])
		if !filepath.IsAbs(exe) || !filepath.IsAbs(dir) || !filepath.IsAbs(userDir) || !filepath.IsAbs(machineDir) {
			return nil, fmt.Errorf("startup tasks require absolute installation paths")
		}
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			return nil, err
		}
		sid := user.User.Sid.String()
		args := `--root ` + windows.EscapeArg(dir) + ` --user-data ` + windows.EscapeArg(userDir) + ` --machine-data ` + windows.EscapeArg(machineDir)
		server := taskXML("Starts the Net Switch service. Net Switch runs this when you open it, so Windows doesn’t ask for permission each time.", "", "HighestAvailable", exe, args, dir, sid)
		signin := taskXML("Starts Net Switch when you sign in. Turn this off in Net Switch’s settings.", `<LogonTrigger><Enabled>true</Enabled><UserId>`+xmlEscape(sid)+`</UserId><Delay>PT5S</Delay></LogonTrigger>`, "LeastPrivilege", exe, "--background "+args, dir, sid)
		if err := folder.discard("RegisterTask", 1, "Server", server, 6, nil, nil, 3, nil); err != nil {
			return nil, err
		}
		return nil, folder.discard("RegisterTask", 1, "Sign-in", signin, 6, nil, nil, 3, nil)
	})
	return err
}
func RunServerTask() error {
	_, err := comThread(func() (any, error) {
		s, err := taskService()
		if err != nil {
			return nil, err
		}
		defer s.release()
		folder, err := s.object("GetFolder", 1, `\Net Switch`)
		if err != nil {
			return nil, err
		}
		defer folder.release()
		task, err := folder.object("GetTask", 1, "Server")
		if err != nil {
			return nil, err
		}
		defer task.release()
		return nil, task.discard("Run", 1, nil)
	})
	return err
}

// A legacy 0.3.0 task ran node.exe with a console. Keep the existing principal,
// sign-in type and arguments while applying the same helper upgrade as Node.
// Unknown task actions are never overwritten during startup.
func upgradeTask(a map[string]any) (any, error) {
	return comThread(func() (any, error) {
		s, err := taskService()
		if err != nil {
			return nil, err
		}
		defer s.release()
		folder, err := s.object("GetFolder", 1, `\Net Switch`)
		if err != nil {
			if missingCOM(err) {
				return "absent", nil
			}
			return nil, err
		}
		defer folder.release()
		task, err := folder.object("GetTask", 1, "Server")
		if err != nil {
			if missingCOM(err) {
				return "absent", nil
			}
			return nil, err
		}
		defer task.release()
		definition, err := task.object("Definition", 2)
		if err != nil {
			return nil, err
		}
		defer definition.release()
		actions, err := definition.object("Actions", 2)
		if err != nil {
			return nil, err
		}
		defer actions.release()
		action, err := actions.object("Item", 2, 1)
		if err != nil {
			return nil, err
		}
		defer action.release()
		path, err := action.text("Path")
		if err != nil {
			return nil, err
		}
		root := js.Text(a["root"])
		helper := filepath.Join(root, "helper", "netswitch-helper.exe")
		node := filepath.Join(root, "runtime", "node.exe")
		if strings.EqualFold(path, helper) || strings.EqualFold(path, js.Text(a["executable"])) {
			return "current", nil
		}
		if !strings.EqualFold(path, node) {
			return "unknown", nil
		}
		args, err := action.text("Arguments")
		if err != nil {
			return nil, err
		}
		if err := action.discard("Arguments", 4, `run "`+node+`" `+args); err != nil {
			return nil, err
		}
		if err := action.discard("Path", 4, helper); err != nil {
			return nil, err
		}
		principal, err := definition.object("Principal", 2)
		if err != nil {
			return nil, err
		}
		defer principal.release()
		logon, err := principal.number("LogonType")
		if err != nil {
			return nil, err
		}
		if err := folder.discard("RegisterTaskDefinition", 1, "Server", definition, 4, nil, nil, logon, nil); err != nil {
			return nil, err
		}
		return "updated", nil
	})
}
