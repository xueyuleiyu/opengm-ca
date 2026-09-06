# openGM-CA Makefile

# 变量定义
BINARY_NAME=opengm-ca
GENCERTS_NAME=gen-certs
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

# 覆盖率闸门阈值（只允许调高，不允许调低）
COVERAGE_MIN ?= 23
COVERAGE_FILE ?= coverage.out
# staticcheck 二进制路径（未安装时自动 go install）
STATICCHECK ?= $(shell go env GOPATH)/bin/staticcheck

# 链接参数
LDFLAGS=-ldflags " \
	-X main.Version=$(VERSION) \
	-X main.BuildTime=$(BUILD_TIME) \
	-X main.GitCommit=$(GIT_COMMIT) \
	-s -w"

# 默认目标
.PHONY: all build build-server build-gen-certs clean test test-short coverage fmt fmt-check vet staticcheck lint coverage-gate check-db-env verify verify-nodb mod docker docker-push install uninstall init-db init-ca run run-dev generate check release help

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
build: build-server build-gen-certs

## build-server: 构建CA服务主程序
build-server:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/ca-server

## build-gen-certs: 构建证书生成工具
build-gen-certs:
	@echo "Building $(GENCERTS_NAME)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(GENCERTS_NAME) ./cmd/gen-certs

## clean: 清理构建产物
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	@rm -rf $(BUILD_DIR)
	@rm -rf ./dist

## test: 运行单元测试（禁用缓存，生成覆盖率）
test:
	@echo "Running tests..."
	$(GOTEST) -count=1 -coverprofile=$(COVERAGE_FILE) ./...

## test-short: 运行快速测试（-short 跳过数据库测试，生成覆盖率）
test-short:
	@echo "Running short tests..."
	$(GOTEST) -short -count=1 -coverprofile=$(COVERAGE_FILE) ./...

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

## fmt-check: 检查Go代码格式（只读检查，不自动改写）
fmt-check:
	@echo "Checking gofmt..."
	@unformatted=$$(gofmt -l $$(go list -f '{{.Dir}}' ./...)); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt -l 发现未格式化文件:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	@echo "gofmt check passed"

## staticcheck: 运行staticcheck静态分析（未安装则自动安装）
staticcheck:
	@echo "Running staticcheck..."
	@if [ ! -x "$(STATICCHECK)" ]; then \
		echo "staticcheck 未安装，正在安装..."; \
		$(GOCMD) install honnef.co/go/tools/cmd/staticcheck@latest; \
	fi
	$(STATICCHECK) ./...

## coverage-gate: 覆盖率闸门（总覆盖率低于 COVERAGE_MIN 即失败）
coverage-gate:
	@echo "覆盖率闸门：要求总覆盖率 >= $(COVERAGE_MIN)%"
	@total=$$($(GOCMD) tool cover -func=$(COVERAGE_FILE) | awk '/^total:/{print $$3}' | tr -d '%'); \
	if [ -z "$$total" ]; then \
		echo "错误：无法从 $(COVERAGE_FILE) 读取 total 覆盖率"; \
		exit 1; \
	fi; \
	echo "实测总覆盖率: $$total%"; \
	if ! awk -v cov="$$total" -v min="$(COVERAGE_MIN)" 'BEGIN { exit !(cov >= min) }'; then \
		echo "失败：覆盖率 $$total% 低于阈值 $(COVERAGE_MIN)%"; \
		exit 1; \
	fi; \
	echo "通过：覆盖率 $$total% >= 阈值 $(COVERAGE_MIN)%"

## check-db-env: 校验 DB_PASSWORD 已设置（数据库测试前置）
check-db-env:
	@if [ -z "$$DB_PASSWORD" ]; then \
		echo "DB_PASSWORD 未设置，请先 export 或 source .env"; \
		exit 1; \
	fi

## verify: 完整验收闸门（含数据库测试，需 DB_PASSWORD）
verify: check-db-env fmt-check vet staticcheck build test coverage-gate
	@echo "verify 通过：6 项检查全部通过"

## verify-nodb: 离线验收闸门（-short 跳过数据库测试）
verify-nodb: fmt-check vet staticcheck build test-short coverage-gate
	@echo "verify-nodb 通过：6 项检查全部通过"

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
	@cp $(BUILD_DIR)/$(GENCERTS_NAME) /usr/local/bin/
	@echo "Installation complete"

## uninstall: 从系统卸载
uninstall:
	@echo "Uninstalling..."
	@rm -f /usr/local/bin/$(BINARY_NAME)
	@rm -f /usr/local/bin/$(GENCERTS_NAME)

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
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o dist/$(GENCERTS_NAME)-linux-amd64 ./cmd/gen-certs
	# Linux arm64
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-arm64 ./cmd/ca-server
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o dist/$(GENCERTS_NAME)-linux-arm64 ./cmd/gen-certs
	# 打包
	@cp -r configs dist/
	@cp -r scripts dist/
	@tar -czf dist/opengm-ca-$(VERSION).tar.gz -C dist .
	@echo "Release built: dist/opengm-ca-$(VERSION).tar.gz"
