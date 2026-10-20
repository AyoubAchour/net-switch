package service

import "github.com/AyoubAchour/net-switch/internal/wintrust"

func checkInstalledPath(path string, ancestor bool) error { return wintrust.Path(path, ancestor) }
