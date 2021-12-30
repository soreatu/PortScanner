package main

import (
	"portscanner/internal/api"
)

func main() {
	// 前端展示
	//go http.ListenAndServe(":8080", http.FileServer(http.Dir("frontend/")))

	// 后端路由
	r := api.NewRouter()
	r.Run(":8081")
}
