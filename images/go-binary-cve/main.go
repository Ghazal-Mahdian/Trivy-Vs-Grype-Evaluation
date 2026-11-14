package main

import (
	"fmt"
	"net/http"
	"os"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

// Nothing here is ever run in the test: the program only has to LINK the
// three modules so they appear in the binary's embedded build info.
func main() {
	var cfg map[string]any
	_ = yaml.Unmarshal([]byte("name: demo\n"), &cfg)

	tok := jwt.New(jwt.SigningMethodHS256)

	up := websocket.Upgrader{}
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c.Close()
	})

	fmt.Println(cfg["name"], tok.Method.Alg(), len(os.Args))
}
