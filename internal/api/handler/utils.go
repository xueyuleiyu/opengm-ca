package handler

import (
	"strconv"

	"github.com/gin-gonic/gin"
)

// getCurrentUser 从 gin 上下文中提取当前用户名，若未设置则返回 "anonymous"
func getCurrentUser(c *gin.Context) string {
	username, _ := c.Get("username")
	if u, ok := username.(string); ok && u != "" {
		return u
	}
	return "anonymous"
}

// parsePaginationParams 统一解析分页参数，返回 page, pageSize, offset
func parsePaginationParams(c *gin.Context, defaultPageSize int) (page, pageSize, offset int) {
	page, _ = strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ = strconv.Atoi(c.DefaultQuery("page_size", strconv.Itoa(defaultPageSize)))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = defaultPageSize
	}
	if pageSize > 100 {
		pageSize = 100
	}
	offset = (page - 1) * pageSize
	return page, pageSize, offset
}
