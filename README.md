## Introduction

端口扫描器，支持TCP<del>、UDP</del>、ICMP协议的多线程扫描

## 架构

- Vue
- Golang/gin

![architecture](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/2021-12-23-22-56-06-image.png)



## demo
![demo](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/iu8PW9.png)


## Scan

### UDP Scan
- 发送UDP数据包
- CLOSE：回icmp unreachable
- OPEN: 

### ICMP Scan
- 发送Echo包
- 有Echo回包则OPEN
- 否则CLOSE

## Issues

### issue1

`for () { go func() }` 还没跑完程序就结束了

solution: 加`sync.WaitGroup`

### issue2

`SetOpen`始终无法修改open这个状态

solution：方法要传入指针，才能对原始的结构体成员进行修改

## TODO

- [x] parser解析IP段+端口段

- [x] 前端

- [x] 衔接组合 ok

进阶：

- [ ] TCP-SYN半连接扫描

- [x] UDP协议

- [x] ICMP协议

- [ ] 前端 错误细化

- [ ] 前端进度条

