# SetupLens

**在執行陌生專案前，先看懂它的安裝與啟動需求。**

SetupLens 讀取本機專案的設定檔，整理工具版本、容器服務、環境變數名稱及指令入口，並附上來源檔案與行號。支援 Node.js、Python、Rust 和 Docker 的部分常見設定；不執行目標程式、不使用模型、不連網。

[English](README.md) · [示範報告](docs/demo-report.html)

## 立即試用

需要 Python 3.11 以上，在 SetupLens 資料夾內執行：

```console
python -m setuplens examples/atlas-demo
python -m setuplens examples/atlas-demo --format html -o setup-report.html
```

用瀏覽器開啟產生的 `setup-report.html`。將 `examples/atlas-demo` 換成另一個本機專案的路徑，就能分析該專案。示範資料夾只供分析，不是可啟動的應用程式。

報告先整理四件事：

1. 專案宣告的工具與版本。
2. 容器映像與連接埠設定。
3. 環境範例檔中的變數名稱；不輸出變數值。
4. npm scripts、Python 入口、Cargo 建置腳本、Make/Just 目標。

後半部提供需要閱讀的安裝與設定提醒，可依等級篩選或搜尋。每項附上來源位置及檢查建議。

## 目前限制

這是初期版本。它整理的是原始設定宣告，沒有驗證安裝順序、工具是否已安裝、外部服務是否可用，也不能保證程式安全。Shell、Compose、workflow 及 Rust 腳本只做部分文字規則分析，動態產生的行為可能漏掉；manifest 行號也可能因重複鍵或特殊格式而不精確。

預設略過真正的 `.env`、依賴與建置目錄、符號連結及 Windows reparse points。其他檔案內的敏感值只能盡力遮蔽，分享報告前應自行檢視。完整範圍見 [coverage](docs/coverage.md)。

此版本尚未於 PyPI 發佈。請下載原始碼並按照上方指令使用；完整 CLI 參數與貢獻方式見 [English README](README.md)。
