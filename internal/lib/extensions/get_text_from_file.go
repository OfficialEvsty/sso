package extensions

import (
	"io"
	"os"
)

// GetTextFromFile extracts text from file .txt
func GetTextFromFile(path string) string {
	file, err := os.Open(path)
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			return
		}
	}(file)
	if err != nil {
		return ""
	}
	data := make([]byte, 512)
	var str string
	for {
		n, err := file.Read(data)
		if err != nil && err != io.EOF {
			break
		}
		str = string(data[:n])
		if err != nil {
			break
		}
	}
	return str
}
