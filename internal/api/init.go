package api

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"portscanner/internal/middleware"
)

func NewRouter() *gin.Engine{
	r := gin.Default()

	// 跨域
	r.Use(middleware.Cors())


	v1 := r.Group("/api/v1")
	{
		v1.GET("/ping", Ping)

		// 扫描请求
		v1.POST("/scan", Scan)
	}


	return r
}


func Ping(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"msg": "pong"})
}



