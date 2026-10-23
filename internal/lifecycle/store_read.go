package lifecycle

import "github.com/AyoubAchour/net-switch/internal/sharedfile"

func readStoreFile(path string) ([]byte, error) { return sharedfile.ReadFile(path, 4<<20) }
