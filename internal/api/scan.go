package api

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"portscanner/internal/log"
	"portscanner/internal/scanner"
)

func Scan(c *gin.Context) {
	// 解析request请求的数据
	var request ScanRequest
	err := c.BindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "bad request data"})
		return
	}

	log.Log().Debug("Get post data `protocol`: %s", request.Protocol)
	log.Log().Debug("Get post data `ip`: %s", request.IP)
	log.Log().Debug("Get post data `port`: %s", request.Port)

	// 解析用户输入的IP字段
	ips, err := scanner.ParseIP(request.IP)
	if err != nil {
		log.Log().Error("Parsing IP got error: %s", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"msg": "bad request data"})
		return
	}
	// 解析用户输入的Port字段
	ports, err := scanner.ParsePort(request.Port)
	if err != nil {
		log.Log().Error("Parsing Port got error: %s", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"msg": "bad request data"})
		return
	}

	// 汇总，生成三元组
	var tuples []scanner.Tuple
	for i := 0; i < len(ips); i++ {
		for j := 0; j < len(ports); j++ {
			tuples = append(tuples, scanner.NewTuple(ips[i], ports[j], request.Protocol))
		}
		// 限制扫描的最大数量
		if len(tuples) > 10000 {
			break
		}
	}

	log.Log().Info(
		"Starting to scan %s protocol with %d lines of data...",
		request.Protocol,
		len(tuples),
	)

	// 多线程对三元组逐一进行扫描
	switch request.Protocol {
	case "tcp":
		tuples = scanner.ScanTCP(tuples)
	case "udp":
		tuples = scanner.ScanUDP(tuples)
	case "icmp":
		tuples = scanner.ScanICMP(tuples)
	default:
		log.Log().Error("Unknown protocol: %s", request.Protocol)
		c.JSON(http.StatusBadRequest, gin.H{"msg": "unknown protocol", "data": nil})
		return
	}

	log.Log().Info("Response with %d lines of data", len(tuples))

	c.JSON(http.StatusOK, gin.H{"msg": "scan succeeded", "data": tuples})
}

// ScanRequest 表示一个Scan请求的数据结构
type ScanRequest struct {
	Protocol string `json:"protocol"`
	IP       string `json:"ip"`
	Port     string `json:"port"`
}
