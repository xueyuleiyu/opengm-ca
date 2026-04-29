# openGM-CA Makefile

# 变量定义
BINARY_NAME=opengm-ca
CLI_NAME=opengm-ca-cli
INIT_NAME=opengm-ca-init
BUILD_DIR=./build
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go参数
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# 链接参数
LDFLAGS=-ldflags " \
	-X main.Version=$(VERSION) \
	-X main.BuildTime=$(BUILD_TIME) \
	-X main.GitCommit=$(GIT_COMMIT) \
	-s -w"

# 默认目标
.PHONY: all build build-server build-cli build-init clean test lint fmt vet docker help

all: build

## help: 显示帮助信息
help:
	@echo "openGM-CA 构建工具"
	@echo ""
	@echo "使用方法: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

## build: 构建所有二进制文件
build: build-server build-cli build-init

## build-server: 构建CA服务主程序
build-server:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/ca-server

## build-cli: 构建CA命令行工具
build-cli:
	@echo "Building $(CLI_NAME)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(CLI_NAME) ./cmd/ca-cli

## build-init: 构建CA初始化工具
build-init:
	@echo "Building $(INIT_NAME)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(INIT_NAME) ./cmd/ca-init

## clean: 清理构建产物
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	@rm -rf $(BUILD_DIR)
	@rm -rf ./dist

## test: 运行单元测试
test:
	@echo "Running tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

## test-short: 运行快速测试
test-short:
	@echo "Running short tests..."
	$(GOTEST) -short ./...

## coverage: 生成测试覆盖率报告
coverage: test
	@echo "Generating coverage report..."
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## fmt: 格式化Go代码
fmt:
	@echo "Formatting..."
	$(GOCMD) fmt ./...

## vet: 运行go vet
vet:
	@echo "Running go vet..."
	$(GOCMD) vet ./...

## lint: 运行golangci-lint
lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed" && exit 1)
	golangci-lint run ./...

## mod: 下载并整理Go依赖
mod:
	@echo "Tidying modules..."
	$(GOMOD) download
	$(GOMOD) tidy
	$(GOMOD) verify

## docker: 构建Docker镜像
docker:
	@echo "Building Docker image..."
	docker build -t opengm-ca:$(VERSION) -f deployments/docker/Dockerfile .

## docker-push: 推送Docker镜像
docker-push: docker
	@echo "Pushing Docker image..."
	docker tag opengm-ca:$(VERSION) opengm-ca:latest
	# docker push your-registry/opengm-ca:$(VERSION)

## install: 安装到系统
install: build
	@echo "Installing to /usr/local/bin..."
	@cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@cp $(BUILD_DIR)/$(CLI_NAME) /usr/local/bin/
	@cp $(BUILD_DIR)/$(INIT_NAME) /usr/local/bin/
	@echo "Installation complete"

## uninstall: 从系统卸载
uninstall:
	@echo "Uninstalling..."
	@rm -f /usr/local/bin/$(BINARY_NAME)
	@rm -f /usr/local/bin/$(CLI_NAME)
	@rm -f /usr/local/bin/$(INIT_NAME)

## init-db: 初始化数据库
init-db: build-server
	@echo "Initializing database..."
	$(BUILD_DIR)/$(BINARY_NAME) -config ./configs/config.yaml -init-db

## init-ca: 初始化CA
init-ca: build-server
	@echo "Initializing CA..."
	$(BUILD_DIR)/$(BINARY_NAME) -config ./configs/config.yaml -init-ca

## run: 运行开发服务器
run:
	@echo "Running development server..."
	$(GOCMD) run ./cmd/ca-server -config ./configs/config.yaml

## run-dev: 以调试模式运行
run-dev:
	@echo "Running in debug mode..."
	LOG_LEVEL=debug $(GOCMD) run ./cmd/ca-server -config ./configs/config.yaml

## generate: 生成代码(generate mocks等)
generate:
	@echo "Generating code..."
	$(GOCMD) generate ./...

## check: 运行所有检查
 check: fmt vet lint test
	@echo "All checks passed!"

# 发布相关
.PHONY: release

## release: 构建发布版本
release: clean
	@echo "Building release..."
	@mkdir -p dist
	# Linux amd64
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64 ./cmd/ca-server
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o dist/$(CLI_NAME)-linux-amd64 ./cmd/ca-cli
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o dist/$(INIT_NAME)-linux-amd64 ./cmd/ca-init
	# Linux arm64
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-arm64 ./cmd/ca-server
	# 打包
	@cp -r configs dist/
	@cp -r scripts dist/
	@tar -czf dist/opengm-ca-$(VERSION).tar.gz -C dist .
	@echo "Release built: dist/opengm-ca-$(VERSION).tar.gz"
